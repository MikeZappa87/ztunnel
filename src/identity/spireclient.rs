use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient};
use tonic::async_trait;
use tracing_subscriber::field::debug;
use crate::{identity::{manager::Identity, CompositeId, RequestKeyEnum}, tls::{self, Certificate, WorkloadCertificate}};
use crate::identity::Error;

pub struct SpireClient {
    client: DelegatedIdentityClient,
}

impl SpireClient {
    pub fn new(client: DelegatedIdentityClient) -> Result<SpireClient, Error> {
        Ok(SpireClient { client })
    }

    pub async fn get_cert(&self, id: &RequestKeyEnum) -> Result<tls::WorkloadCertificate, Error> {

        match id {
           RequestKeyEnum::Pid(id) => {
              let pid = id.into_i32();

              tracing::debug!("Fetching SVID for PID: {}", pid);

              let req = self.client.clone()
                    .fetch_x509_svid(spire_api::DelegateAttestationRequest::Pid(pid))
                    .await
                    .map_err(|e| Error::Spiffe(format!("Failed to fetch SVID: {}", e)))?;

                tracing::debug!("Fetched SVID for PID: {}", pid);
                tracing::debug!("Private key: {:?}", req.private_key().content());
                tracing::debug!("Leaf cert: {:?}", req.leaf().content());
                tracing::debug!("SPIFFE ID: {}", req.spiffe_id());
                //I need to dump the cert chain here too.
                tracing::debug!("Certs in chain: {}", req.cert_chain().len());
                tracing::debug!("Cert chain:");
                for (i, cert) in req.cert_chain().iter().enumerate() {
                    tracing::debug!("Cert {}: {:?}", i, cert.content());
                }

                let certs = tls::WorkloadCertificate::new_svid(req)
                    .map_err(|e| Error::Spiffe(format!("Failed to create WorkloadCertificate: {}", e)))?;
                Ok(certs)
           },
           _ => return Err(Error::Spiffe("Unsupported RequestKeyEnum variant".into())),
        }
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for SpireClient {
    async fn fetch_certificate(&self, id: &CompositeId<RequestKeyEnum>) -> Result<tls::WorkloadCertificate, Error> {
        self.get_cert(id.key()).await
    }
}

pub mod tests {
    use spire_api::DelegatedIdentityClient;
    use crate::identity::{self, *};
    use crate::identity::{CaClientTrait, SpireClient};
    use crate::inpod::WorkloadPid;

    #[tokio::test]
    async fn test_spire_client() {
        // This is a placeholder for actual tests.
        // You would typically mock the DelegatedIdentityClient and test the SpireClient methods.

        let client = DelegatedIdentityClient::new_from_path("unix:///tmp/spire-agent/private/admin.sock").await.unwrap();

        let spire_client = SpireClient::new(client).unwrap();

        let id = Identity::Spiffe { trust_domain: "example.org".into(), namespace: "myservice".into(), service_account: "default".into() };

        let comp = CompositeId::new(id.clone(), RequestKeyEnum::Pid(WorkloadPid::new(790343)));

       let item = spire_client.fetch_certificate(&comp).await.unwrap();
       
       assert_ne!(item.chain.len(), 0);
       assert_ne!(item.roots.len(), 0);
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod mock {
    use std::{sync::Arc, time::Instant};

    use mockall::{automock, predicate::always};
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

            let certs = WorkloadCertificate::new_svid(req).unwrap();
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