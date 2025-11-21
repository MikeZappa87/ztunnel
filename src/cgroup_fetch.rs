use std::error::Error;
use std::fmt;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::SystemTime;
use std::time::{Duration, Instant};

use tonic::async_trait;

use crate::identity::PidClientTrait;
use crate::identity::WorkloadPid;
use crate::inpod::WorkloadUid;

/// Errors that can occur while locating the pause PID from a cgroup.
#[derive(Debug)]
pub enum CgroupErr {
    ReadDir { dir: PathBuf, source: io::Error },
    Stat { path: PathBuf, source: io::Error },
    NotFound { dir: PathBuf },
    Open { path: PathBuf, source: io::Error },
    Read { path: PathBuf, source: io::Error },
    ParsePid { token: String },
    EmptyProcs { path: PathBuf },
}
//TODO SUPPORT crio and dockerd cgroup layouts
pub struct CgroupManager {}
#[async_trait]
impl PidClientTrait for CgroupManager {
    async fn fetch_pid(&self, uid: &WorkloadUid) -> Result<WorkloadPid, std::io::Error> {
        // Assume cgroup v1 and kubelet.slice as root
        let (pid, _scope) = get_pause_pid("/sys/fs/cgroup/kubepods.slice", &uid.clone().into_string()).map_err(|e| std::io::Error::new(std::io::ErrorKind::NotFound, e.to_string()))?;

        Ok(WorkloadPid::new(pid))
    }
}

impl fmt::Display for CgroupErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use CgroupErr::*;
        match self {
            ReadDir { dir, .. } => write!(f, "failed to read directory: {}", dir.display()),
            Stat { path, .. } => write!(f, "failed to stat path: {}", path.display()),
            NotFound { dir } => write!(f, "no cri-containerd-*.scope dir under {}", dir.display()),
            Open { path, .. } => write!(f, "failed to open file: {}", path.display()),
            Read { path, .. } => write!(f, "failed to read file: {}", path.display()),
            ParsePid { token } => write!(f, "failed to parse PID from token: {}", token),
            EmptyProcs { path } => write!(f, "no PID found (empty cgroup.procs) at {}", path.display()),
        }
    }
}
impl Error for CgroupErr {}

/// Normalize Pod UID: replace `-` with `_`.
fn normalize_pod_uid(uid: &str) -> String {
    uid.replace('-', "_")
}
/// root = /sys/fs/cgroup
/// Build candidate pod slice directories across QoS classes, matching kubelet naming:
/// - guaranteed:  <root>/kubelet-kubepods.slice/kubelet-kubepods-pod<uid>.slice
/// - besteffort:  <root>/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod<uid>.slice
/// - burstable:   <root>/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod<uid>.slice
fn pod_cgroup_candidates(root: &str, pod_uid: &str) -> Vec<PathBuf> {
    let uid_norm = normalize_pod_uid(pod_uid);
    let mut out = Vec::with_capacity(3);

    // guaranteed
    out.push(
        PathBuf::from(root)
            .join(format!("kubepods-pod{}.slice", uid_norm)),
    );

    // besteffort
    out.push(
        PathBuf::from(root)
            .join("kubepods-besteffort.slice")
            .join(format!("kubepods-besteffort-pod{}.slice", uid_norm)),
    );

    // burstable
    out.push(
        PathBuf::from(root)
            .join("kubepods-burstable.slice")
            .join(format!("kubepods-burstable-pod{}.slice", uid_norm)),
    );

    out
}

/// Public API: takes root cgroup base (e.g. "/sys/fs/cgroup/kubelet.slice") and Pod UID,
/// finds the pause PID. Returns (pid, scope_dir).
pub fn get_pause_pid(root: &str, pod_uid: &str) -> Result<(i32, PathBuf), CgroupErr> {
    for candidate in pod_cgroup_candidates(root, pod_uid) {
        if !candidate.exists() {
            tracing::debug!("pod cgroup not found: {}", candidate.display());
            continue;
        }
        match get_pause_pid_from_pod_cgroup(&candidate) {
            Ok(res) => return Ok(res),
            Err(CgroupErr::NotFound { .. }) => continue, // try next candidate
            Err(e) => return Err(e),
        }
    }
    Err(CgroupErr::NotFound {
        dir: PathBuf::from(root),
    })
}

/// Core logic: scan a specific pod slice dir for "cri-containerd-*.scope" and read first PID.
fn get_pause_pid_from_pod_cgroup(pod_slice_dir: &Path) -> Result<(i32, PathBuf), CgroupErr> {
   // let scope_dir = find_first_cri_containerd_scope(pod_slice_dir)?;

   let scope_dir = find_oldest_cri_containerd_scope(pod_slice_dir)?;

    let cg_procs = scope_dir.join("cgroup.procs");

    tracing::debug!("Reading pause PID from {}", cg_procs.display());

    // Short retry loop: scope may exist briefly before cgroup.procs has content.
    let total_wait = Duration::from_secs(2);
    let interval = Duration::from_millis(100);
    let deadline = Instant::now() + total_wait;

    loop {
        match read_first_pid(&cg_procs) {
            Ok(pid) => return Ok((pid, scope_dir)),
            Err(CgroupErr::Open { .. }) | Err(CgroupErr::EmptyProcs { .. }) => {
                if Instant::now() >= deadline {
                    return Err(CgroupErr::EmptyProcs { path: cg_procs });
                }
                thread::sleep(interval);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Find the oldest cri-containerd-*.scope by directory mtime.
/// If mtime can't be read, we treat it as very new (to avoid false "oldest").
/// Returns the scope dir path.
fn find_oldest_cri_containerd_scope(dir: &Path) -> Result<PathBuf, CgroupErr> {
    let mut oldest: Option<(SystemTime, PathBuf)> = None;

    let iter = fs::read_dir(dir)
        .map_err(|e| CgroupErr::ReadDir { dir: dir.to_path_buf(), source: e })?;

    for entry in iter {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().into_owned();
        if !(name.starts_with("cri-containerd-") && name.ends_with(".scope")) {
            continue;
        }
        let p = entry.path();
        let md = fs::metadata(&p)
            .map_err(|e| CgroupErr::Stat { path: p.clone(), source: e })?;
        if !md.is_dir() {
            continue;
        }

        // Prefer directory mtime; if unavailable, use UNIX_EPOCH as "very old" or "very new"
        // Strategy: if we can't read mtime, treat as "new" so it won't win accidentally.
        let mtime = md.modified().unwrap_or(SystemTime::now());

        match &mut oldest {
            Some((best_time, best_path)) => {
                if mtime > *best_time {
                    *best_time = mtime;
                    *best_path = p;
                }
            }
            None => oldest = Some((mtime, p)),
        }
    }

    oldest
        .map(|(_, p)| p)
        .ok_or_else(|| CgroupErr::NotFound { dir: dir.to_path_buf() })
}

fn read_first_pid(cgroup_procs_path: &Path) -> Result<i32, CgroupErr> {
    let file = fs::File::open(cgroup_procs_path)
        .map_err(|e| CgroupErr::Open { path: cgroup_procs_path.to_path_buf(), source: e })?;
    let reader = io::BufReader::new(file);

    for line_res in reader.lines() {
        let line = line_res
            .map_err(|e| CgroupErr::Read { path: cgroup_procs_path.to_path_buf(), source: e })?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Only take the first token, ignore extras
        if let Some(first) = trimmed.split_whitespace().next() {
            let pid: i32 = first.parse().map_err(|_| CgroupErr::ParsePid { token: first.to_string() })?;
            return Ok(pid);
        }
    }
    Err(CgroupErr::EmptyProcs { path: cgroup_procs_path.to_path_buf() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn parses_first_pid_from_scope() {
        let td = tempdir().unwrap();
        let root = td.path().join("kubepods.slice");
        fs::create_dir_all(&root).unwrap();

        // Simulate guaranteed QoS path
        let pod_uid = "39bed253-13ee-41a5-b9b7-3773c8135bce";
        let norm = normalize_pod_uid(pod_uid);
        let pod_dir = root.join(format!("kubepods-pod{}.slice", norm));
        fs::create_dir_all(&pod_dir).unwrap();

        let scope = pod_dir.join("cri-containerd-4d15a3052206cf07036d0c3e91beec3baf8da145def7ab9ac45c91edb3a7d8bc.scope");
        fs::create_dir(&scope).unwrap();

        let procs = scope.join("cgroup.procs");
        let mut f = File::create(&procs).unwrap();
        writeln!(f, "1234").unwrap();

        let (pid, found_scope) = get_pause_pid(root.to_str().unwrap(), pod_uid).unwrap();
        assert_eq!(pid, 1234);
        assert_eq!(found_scope, scope);
    }

    #[test]
    fn returns_first_when_multiple_pids_present() {
        let td = tempdir().unwrap();
        let root = td.path().join("kubepods.slice");
        fs::create_dir_all(&root).unwrap();

        // Simulate burstable QoS path
        let pod_uid = "41473cc5-5cec-450d-9dca-805ce45455d5";
        let norm = normalize_pod_uid(pod_uid);
        let pod_dir = root
            .join("kubepods-burstable.slice")
            .join(format!("kubepods-burstable-pod{}.slice", norm));
        fs::create_dir_all(&pod_dir).unwrap();

        let scope = pod_dir.join("cri-containerd-4d15a3052206cf07036d0c3e91beec3baf8da145def7ab9ac45c91edb3a7d8bc.scope");
        fs::create_dir(&scope).unwrap();

        let procs = scope.join("cgroup.procs");
        let mut f = File::create(&procs).unwrap();
        writeln!(f, "2222\n3333\n").unwrap(); // multiple PIDs

        let (pid, _) = get_pause_pid(root.to_str().unwrap(), pod_uid).unwrap();
        assert_eq!(pid, 2222); // first pid only
    }

    #[test]
    fn tries_qos_candidates_and_errors_if_missing() {
        let td = tempdir().unwrap();
        let root = td.path().join("kubepods.slice");
        fs::create_dir_all(&root).unwrap();

        let err = get_pause_pid(root.to_str().unwrap(), "does-not-exist-uid").unwrap_err();
        match err {
            CgroupErr::NotFound { .. } => {}
            _ => panic!("expected NotFound"),
        }
    }

    #[test]
    fn picks_oldest_scope_by_mtime() {
        use std::fs::{self, File};
        use std::thread;
        use std::time::Duration;

        let td = tempfile::tempdir().unwrap();
        let pod_dir = td.path();

        // First scope dir
        let scope1 = pod_dir.join("cri-containerd-aaa.scope");
        fs::create_dir(&scope1).unwrap();
        File::create(scope1.join("cgroup.procs")).unwrap();
        // sleep so next dir has newer mtime
        thread::sleep(Duration::from_millis(50));

        // Second scope dir
        let scope2 = pod_dir.join("cri-containerd-bbb.scope");
        fs::create_dir(&scope2).unwrap();
        File::create(scope2.join("cgroup.procs")).unwrap();
        thread::sleep(Duration::from_millis(50));

        // Third scope dir
        let scope3 = pod_dir.join("cri-containerd-ccc.scope");
        fs::create_dir(&scope3).unwrap();
        File::create(scope3.join("cgroup.procs")).unwrap();

        // Run function under test
        let oldest = super::find_oldest_cri_containerd_scope(pod_dir).unwrap();

        // Should return the last one created (scope3)
        assert_eq!(oldest.file_name().unwrap().to_str().unwrap(), "cri-containerd-ccc.scope");
    }

    #[test]
    fn read_cgroup_procs() {
        let path = PathBuf::from("/sys/fs/cgroup/cgroup.procs");
        let pid = read_first_pid(&path).unwrap();
        assert_eq!(pid, 1);
    }
}


// /sys/fs/cgroup/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podd7d2ffc1_afea_42bb_ba42_73d64f022919.slice/cri-containerd-8b09a98bc5fbdb094e530675dd39d3d6c1e0c496b4622561c845024d9d411e14.scope/cgroup.procs