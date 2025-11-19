use std::sync::Arc;

use spiffe::{error::GrpcClientError, TrustDomain, X509Svid};
use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient, selectors::{K8s, Selector}};
use tonic::async_trait;
use crate::{config::Config, identity::{ CompositeId, Identity, PidClientTrait, RequestKeyEnum}, inpod::WorkloadPid, tls::{self}};
use crate::identity::Error;
use backoff::{Error as BError, ExponentialBackoff};

pub struct SpireClient {
    client: DelegatedIdentityClient,
    trust_domain: String,
    pid: Box<dyn PidClientTrait>,
    cfg: Arc<Config>
}

impl SpireClient {
    pub fn new(client: DelegatedIdentityClient, trust_domain: String, pid: Box<dyn PidClientTrait>, cfg: Arc<Config>) -> Result<SpireClient, Error> {
        Ok(SpireClient { client, trust_domain, pid, cfg })
    }

    pub async fn get_cert_by_pid(&self, pid: &WorkloadPid) -> Result<tls::WorkloadCertificate, Error> {
        let pid = pid.into_i32();
        tracing::debug!("Fetching SVID for PID: {}", pid);

        let req = self.call_fetch_with_retry(pid).await?;

        tracing::debug!("Fetched SVID for PID: {}", pid);

        // We need to move the bundle fetching out of this function, as it is called multiple times.
        // We can cache the bundle in the SpireClient struct.
        // For now, we will fetch the bundle each time.
        let bundle = self.get_bundle().await?;

        let certs = tls::WorkloadCertificate::new_svid(&req, &bundle)?;

        Ok(certs)
    }

    pub async fn get_cert_by_selector(&self, id: &Identity) -> Result<tls::WorkloadCertificate, Error> {
    
        let mut selectors = Vec::<Selector>::new();
        selectors.push(Selector::K8s(K8s::Namespace(id.ns().to_string())));
        selectors.push(Selector::K8s(K8s::ServiceAccount(id.sa().to_string())));

        let req = self.client.clone()
            .fetch_x509_svid(DelegateAttestationRequest::Selectors(selectors))
            .await
            .map_err(|e| Error::FailedToFetchCertificate(format!("Failed to fetch X.509 SVID: {}", e)))?;

        let bundle = self.get_bundle().await?;

        let certs = tls::WorkloadCertificate::new_svid(&req, &bundle)?;

        Ok(certs)
    }

    async fn get_bundle(&self) -> Result<Vec<spiffe::cert::Certificate>, Error> {
        let bundle_req = self.client.clone().fetch_x509_bundles()
        .await
        .map_err(|e| Error::FailedToFetchBundle(format!("Failed to fetch X.509 bundles: {}", e)))?;

        let td = TrustDomain::new(&self.trust_domain).map_err(|e| Error::InvalidTrustDomain(format!("Invalid trust domain {}: {}", self.trust_domain, e)))?;
        tracing::debug!("Fetched bundle for trust domain: {}", td);

        let bundles = match bundle_req.get_bundle(&td) {
            Some(b) => b.authorities(),
            None => {
                return Err(Error::InvalidTrustDomain(format!("No bundle found for trust domain: {}", td)));
            }
        };

        Ok(bundles.clone())
    }

    async fn call_fetch_with_retry(&self, pid: i32) -> Result<X509Svid, Error> {
        let backoff = ExponentialBackoff {
            initial_interval: std::time::Duration::from_millis(500),
            max_interval: std::time::Duration::from_secs(1),
            max_elapsed_time: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        };

         backoff::future::retry(backoff, || async move {
            let req = self.client.clone()
            .fetch_x509_svid(DelegateAttestationRequest::Pid(pid))
            .await;

            //If req returns an EmptyResponse, we want to treat it as a transient error.
            match req {
                Ok(svid) => Ok(svid),
                Err(GrpcClientError::EmptyResponse) => Err(BError::transient(Error::FailedToFetchPidForWorkload(pid))),
                Err(e) => {
                    tracing::error!("Error fetching SVID for PID {}: {}", pid, e);
                    Err(BError::permanent(Error::FailedToFetchPidForWorkload(pid)))
                }
            }
        }).await
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for SpireClient {
    async fn fetch_certificate(&self, id: &CompositeId<RequestKeyEnum>) -> Result<tls::WorkloadCertificate, Error> {
        match id.key() {
            RequestKeyEnum::Workload(wl_uid) => {

                if self.cfg.spire_mode == crate::config::SpireMode::BySelectors {
                    let identity = id.id();
                    return self.get_cert_by_selector(&identity).await;
                }

                //I need to get the pid from the workload.
                // TODO - Use pidfds to verify the pid has not exited between fetch and get_cert.
                match self.pid.fetch_pid(wl_uid).await {
                    Ok(pid) => {
                        self.get_cert_by_pid(&pid).await
                    }
                    Err(e) => {
                        tracing::error!("Failed to fetch pid for workload {}: {}", wl_uid.clone().into_string(), e);
                        Err(Error::FailedToFetchCertificate(wl_uid.clone().into_string()))
                    }
                }
            }
            _ => Err(Error::UnsupportedKeyFormat(format!("Unsupported key format for id: {:?}", id))),
        }
    }
}