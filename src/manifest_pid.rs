// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::path::PathBuf;

use tonic::async_trait;

use crate::identity::{PidClientTrait, WorkloadPid};
use crate::inpod::WorkloadUid;

/// Manifest JSON structure read from instance directories.
/// Located at `{instances_dir}/{instanceID}/config.json`.
#[derive(serde::Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    /// The shim process ID — this is the PID we need.
    #[serde(alias = "shimProcessId")]
    shim_process_id: i32,
    // Other fields exist but we only need shimProcessId.
}

/// A PID fetcher that reads from manifest.json files on disk.
///
/// For each workload UID, it looks for a manifest file at:
///   `{instances_dir}/{instanceID}/config.json`
///
/// It scans all instance directories under `instances_dir` and reads each
/// `config.json` to find the one whose `id` field matches the workload UID,
/// then returns `shimProcessId` as the PID.
///
/// Alternatively, if the workload UID directly maps to an instance directory name,
/// it reads that directory's manifest directly.
pub struct ManifestPidFetcher {
    instances_dir: PathBuf,
}

impl ManifestPidFetcher {
    pub fn new(instances_dir: String) -> Self {
        Self {
            instances_dir: PathBuf::from(instances_dir),
        }
    }

    /// Try to find the manifest for the given instance ID.
    /// The instance ID (workload UID) may need to be looked up by scanning
    /// subdirectories, or it may match a directory name directly.
    async fn read_manifest(&self, uid: &WorkloadUid) -> Result<Manifest, std::io::Error> {
        let uid_str = uid.clone().into_string();

        // Strategy 1: Try direct path {instances_dir}/{uid}/config.json
        let direct_path = self.instances_dir.join(&uid_str).join("config.json");
        if let Ok(content) = tokio::fs::read_to_string(&direct_path).await {
            let manifest: Manifest = serde_json::from_str(&content).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse manifest at {:?}: {}", direct_path, e),
                )
            })?;
            return Ok(manifest);
        }

        // Strategy 2: Scan all subdirectories for a config.json containing matching id
        let mut entries = tokio::fs::read_dir(&self.instances_dir).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to read instances directory {:?}: {}",
                    self.instances_dir, e
                ),
            )
        })?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("config.json");
            if let Ok(content) = tokio::fs::read_to_string(&manifest_path).await {
                // Check if this manifest's id matches our UID
                #[derive(serde::Deserialize)]
                struct ManifestWithId {
                    id: Option<String>,
                    #[serde(rename = "shimProcessId", alias = "shim_process_id")]
                    shim_process_id: i32,
                }

                if let Ok(m) = serde_json::from_str::<ManifestWithId>(&content) {
                    if m.id.as_deref() == Some(&uid_str) {
                        return Ok(Manifest {
                            shim_process_id: m.shim_process_id,
                        });
                    }
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "No manifest found for workload UID {} in {:?}",
                uid_str, self.instances_dir
            ),
        ))
    }
}

#[async_trait]
impl PidClientTrait for ManifestPidFetcher {
    async fn fetch_pid(&self, uid: &WorkloadUid) -> Result<WorkloadPid, std::io::Error> {
        let manifest = self.read_manifest(uid).await?;

        if manifest.shim_process_id <= 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid shimProcessId {} for workload UID {}",
                    manifest.shim_process_id,
                    uid.clone().into_string()
                ),
            ));
        }

        tracing::info!(
            "Fetched PID {} from manifest for workload UID {}",
            manifest.shim_process_id,
            uid.clone().into_string()
        );

        Ok(WorkloadPid::new(manifest.shim_process_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(feature = "testing")]
    use tempfile::TempDir;

    fn make_manifest_dir(
        base: &std::path::Path,
        instance_id: &str,
        shim_pid: i32,
    ) -> PathBuf {
        let dir = base.join(instance_id);
        fs::create_dir_all(&dir).unwrap();
        let manifest = serde_json::json!({
            "id": instance_id,
            "shimProcessId": shim_pid,
            "bundle": format!("/instances/{}", instance_id),
        });
        fs::write(dir.join("config.json"), manifest.to_string()).unwrap();
        dir
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn test_direct_path_lookup() {
        let tmp = TempDir::new().unwrap();
        let uid_str = "test-instance-123";
        make_manifest_dir(tmp.path(), uid_str, 42);

        let fetcher = ManifestPidFetcher::new(tmp.path().to_string_lossy().to_string());
        let uid = WorkloadUid::new(uid_str.to_string());
        let pid = fetcher.fetch_pid(&uid).await.unwrap();
        assert_eq!(pid.into_i32(), 42);
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn test_scan_lookup() {
        let tmp = TempDir::new().unwrap();
        // Create with a different directory name than the id
        let dir = tmp.path().join("some-container-hash");
        fs::create_dir_all(&dir).unwrap();
        let manifest = serde_json::json!({
            "id": "my-workload-uid",
            "shimProcessId": 99,
        });
        fs::write(dir.join("config.json"), manifest.to_string()).unwrap();

        let fetcher = ManifestPidFetcher::new(tmp.path().to_string_lossy().to_string());
        let uid = WorkloadUid::new("my-workload-uid".to_string());
        let pid = fetcher.fetch_pid(&uid).await.unwrap();
        assert_eq!(pid.into_i32(), 99);
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn test_not_found() {
        let tmp = TempDir::new().unwrap();
        let fetcher = ManifestPidFetcher::new(tmp.path().to_string_lossy().to_string());
        let uid = WorkloadUid::new("nonexistent".to_string());
        let result = fetcher.fetch_pid(&uid).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::NotFound);
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn test_invalid_pid() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("bad-pid");
        fs::create_dir_all(&dir).unwrap();
        let manifest = serde_json::json!({
            "id": "bad-pid",
            "shimProcessId": 0,
        });
        fs::write(dir.join("config.json"), manifest.to_string()).unwrap();

        let fetcher = ManifestPidFetcher::new(tmp.path().to_string_lossy().to_string());
        let uid = WorkloadUid::new("bad-pid".to_string());
        let result = fetcher.fetch_pid(&uid).await;
        assert!(result.is_err());
    }
}
