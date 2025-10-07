use std::io;

use rustls::pki_types::PrivateKeyDer;
use spiffe::{error::GrpcClientError, TrustDomain, X509Svid};
use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient};
use tonic::async_trait;
use crate::{identity::{ CompositeId, RequestKeyEnum}, inpod::WorkloadPid, tls::{self}};
use crate::identity::Error;
use crate::cgroup_fetch::{get_pause_pid};
use backoff::{Error as BError, ExponentialBackoff};

pub struct SpireClient {
    client: DelegatedIdentityClient,
    trust_domain: String,
}

impl SpireClient {
    pub fn new(client: DelegatedIdentityClient, trust_domain: String) -> Result<SpireClient, Error> {
        Ok(SpireClient { client, trust_domain })
    }

    pub async fn get_cert(&self, pid: &WorkloadPid) -> Result<tls::WorkloadCertificate, Error> {
        let pid = pid.into_i32();
        tracing::debug!("Fetching SVID for PID: {}", pid);

        let req = self.call_fetch_with_retry(pid).await?;

        tracing::debug!("Fetched SVID for PID: {}", pid);
        tracing::debug!("SPIFFE ID: {}", req.spiffe_id());
        //I need to dump the cert chain here too.
        tracing::debug!("Certs in chain: {}", req.cert_chain().len());
        //I need to dump the certificates in a readable format.
        for cert in req.cert_chain() {
            let (_, parsed_cert) = x509_parser::parse_x509_certificate(&cert.content()).unwrap();
            tracing::debug!("Parsed Cert: Subject: {}, Issuer: {}, Not Before: {}, Not After: {}", parsed_cert.subject(), parsed_cert.issuer(), parsed_cert.validity().not_before, parsed_cert.validity().not_after);
        }

        //I need to dump the leaf certificate in a readable format.
        let (_, parsed_leaf) = x509_parser::parse_x509_certificate(&req.leaf().content()).unwrap();
        tracing::debug!("Parsed Leaf Cert: Subject: {}, Issuer: {}, Not Before: {}, Not After: {}", parsed_leaf.subject(), parsed_leaf.issuer(), parsed_leaf.validity().not_before, parsed_leaf.validity().not_after);

        //I need to dump the private key in a readable format.
        let pkcs8 = req.private_key().content();
        let parsed_key = PrivateKeyDer::Pkcs8(pkcs8.to_vec().into());
        tracing::debug!("Parsed Private Key: {:?}", parsed_key);

        let bundle = self.get_bundle().await?;

        let certs = tls::WorkloadCertificate::new_svid(req, &bundle)
            .map_err(|e| Error::Spiffe(format!("Failed to create WorkloadCertificate: {}", e)))?;
        Ok(certs)
    }

    async fn get_bundle(&self) -> Result<Vec<spiffe::cert::Certificate>, Error> {
        let bundle_req = self.client.clone().fetch_x509_bundles()
        .await
        .map_err(|e| Error::Spiffe(format!("Failed to fetch X.509 bundles: {}", e)))?;

        let td = TrustDomain::new(&self.trust_domain).map_err(|e| Error::Spiffe(format!("Invalid trust domain {}: {}", self.trust_domain, e)))?;
        tracing::debug!("Fetched bundle for trust domain: {}", td);

        let bundles = bundle_req.get_bundle(&td).unwrap().authorities();

        //The bundle is returning the certificates as a byte array, I need them readable like the above.
        for  cert in bundles {
            let (_, parsed_cert) = x509_parser::parse_x509_certificate(&cert.content()).unwrap();
            tracing::debug!("Parsed Bundle: Subject: {}, Issuer: {}, Not Before: {}, Not After: {}", parsed_cert.subject(), parsed_cert.issuer(), parsed_cert.validity().not_before, parsed_cert.validity().not_after);
        }

        Ok(bundles.clone())
    }

    async fn call_fetch_with_retry(&self, pid: i32) -> Result<X509Svid, Error> {
        let backoff = ExponentialBackoff {
            initial_interval: std::time::Duration::from_millis(500),
            max_interval: std::time::Duration::from_secs(1),
            max_elapsed_time: Some(std::time::Duration::from_secs(5)),
            ..Default::default()
        };

        let f = backoff::future::retry(backoff, || async move {
            self.wrapped_fetch(pid).await
        }).await;

        match f {
            Ok(svid) => Ok(svid),
            Err(e) => Err(Error::Spiffe(format!("Failed to fetch SVID after retries: {}", e))),
        }
    }

    async fn wrapped_fetch(&self, pid: i32) -> Result<X509Svid, BError<Error>> {
       let req = self.get_workload_certs(pid).await;

       //If req returns an EmptyResponse, we want to treat it as a transient error.
       match req {
        Ok(svid) => Ok(svid),
        Err(GrpcClientError::EmptyResponse) => Err(BError::transient(Error::Spiffe("Empty response from SPIRE".into()))),
        Err(e) => Err(BError::permanent(Error::Spiffe(format!("SPIRE error: {}", e)))),
       }
    }

    async fn get_workload_certs(&self, pid: i32) -> Result<X509Svid, GrpcClientError> {
        let req = self.client.clone()
            .fetch_x509_svid(spire_api::DelegateAttestationRequest::Pid(pid))
            .await?;

        Ok(req)
    }

    //This should be a trait function. 
    pub async fn fetch_pid(&self, uid: String) -> io::Result<WorkloadPid> {
        let (pid, path) = get_pause_pid("/sys/fs/cgroup/kubepods.slice", uid.as_str()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("failed to get container pid from cgroup: {}", e),
            )
        })?;

        tracing::debug!("Found container PID: {} Path: {}", pid, path.display());
        
        Ok(WorkloadPid::new(pid))
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for SpireClient {
    async fn fetch_certificate(&self, id: &CompositeId<RequestKeyEnum>) -> Result<tls::WorkloadCertificate, Error> {
        match id.key() {
            RequestKeyEnum::Workload(wl_uid) => {
                //I need to get the pid from the workload.
                match self.fetch_pid(wl_uid.clone().into_string()).await {
                    Ok(pid) => {
                        self.get_cert(&pid).await
                    }
                    Err(e) => Err(Error::Spiffe(format!("Failed to get PID for workload {}: {}", wl_uid.clone().into_string(), e))),
                }
            }
            _ => Err(Error::Spiffe("Unsupported RequestKeyEnum variant".into())),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod tests {
    use spire_api::DelegatedIdentityClient;
    use crate::identity::{self, *};
    use crate::identity::{CaClientTrait, SpireClient};
    use crate::inpod::{WorkloadPid, WorkloadUid};
    use crate::state::workload::Workload;
    use crate::test_helpers;

    #[tokio::test]
    async fn test_spire_client() {
        // This is a placeholder for actual tests.
        // You would typically mock the DelegatedIdentityClient and test the SpireClient methods.

        let client = DelegatedIdentityClient::new_from_path("unix:///tmp/spire-agent/private/admin.sock").await.unwrap();

        let spire_client = SpireClient::new(client, "example.org".into()).unwrap();

        let id = Identity::Spiffe { trust_domain: "example.org".into(), namespace: "myservice".into(), service_account: "default".into() };

        let wl = Workload {
           uid: "test-uid".into(),
           namespace: "myservice".into(),
           service_account: "default".into(),
           native_tunnel: true,
           protocol: crate::state::workload::InboundProtocol::HBONE,
           ..test_helpers::test_default_workload()
        };

        let comp = CompositeId::new(id.clone(), RequestKeyEnum::Workload(WorkloadUid::new(wl.uid.to_string())));

       let item = spire_client.fetch_certificate(&comp).await.unwrap();
       
       assert_ne!(item.chain.len(), 0);
       assert_ne!(item.roots.len(), 0);
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod mock {
    use std::{sync::Arc, time::Instant};

    use mockall::{automock, predicate::always};
    use spiffe::{bundle, X509Bundle};
    use tokio::sync::RwLock;

    use crate::{identity::Identity, time::Converter, tls::WorkloadCertificate};
    use super::*;

     #[derive(Default)]
    struct ClientState {
        fetches: Vec<Identity>,
        error: bool,
        cert_gen: tls::mock::CertGenerator,
    }

    #[automock]
    #[async_trait::async_trait]
    pub trait SpireClientTrait {
        async fn fetch_x509_svid(
            &self,
            req: spire_api::DelegateAttestationRequest,
        ) -> Result<spiffe::X509Svid, spiffe::error::GrpcClientError>;
    }

    pub(crate) struct MockSpireClient {
        state: Arc<RwLock<ClientState>>,
    }

    impl MockSpireClient {
        pub fn new() -> Self {
            MockSpireClient {
                state: Default::default(),
            }
        }
    }

    #[async_trait]
    impl crate::identity::CaClientTrait for MockSpireClient {
        async fn fetch_certificate(
            &self,
            id: &CompositeId<RequestKeyEnum>,
        ) -> Result<tls::WorkloadCertificate, Error> {
            let mut state = self.state.write().await;
            if state.error {
                return Err(Error::Spiffe("injected test error".into()));
            }

            let mut mock = MockSpireClientTrait::new();

            let timeconv = Converter::new();

            let not_before = Instant::now();
            let not_after = not_before + std::time::Duration::from_secs(60);

            let (k,v) = tls::mock::generate_test_certs_with_root(&id.id().to_owned().into(), timeconv.instant_to_system_time(not_before).unwrap(), timeconv.instant_to_system_time(not_after).unwrap(), None, tls::mock::TEST_ROOT);
            state.fetches.push(id.id().to_owned());
            let svid = spiffe::X509Svid::parse_from_der(v.as_bytes(), k.as_bytes()).unwrap();

            mock.expect_fetch_x509_svid().with(always()).returning(move |_req| {
                Ok(svid.clone())
            });

            let req = mock.fetch_x509_svid(DelegateAttestationRequest::Pid(1234)).await.unwrap();

            let bundle = spiffe::bundle::x509::X509Bundle::new(TrustDomain::new("id_or_name").unwrap());

            let certs = WorkloadCertificate::new_svid(req, &bundle.authorities()).unwrap();
            Ok(certs)
            /* 
            let timeconv = Converter::new();

            let not_before = Instant::now();
            let not_after = not_before + std::time::Duration::from_secs(60);

            let certs = state
                .cert_gen
                .new_certs(&id.to_owned().into(), timeconv.instant_to_system_time(not_before).unwrap(), timeconv.instant_to_system_time(not_after).unwrap());
            state.fetches.push(id.to_owned());
            Ok(certs)
            */
        }
    }
}