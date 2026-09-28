// SPDX-License-Identifier: Apache-2.0
//! Integration test: Watch stream reconnection and version monotonicity (Phase 6.2).

use common::certs::TestCa;
use fleetos_agent::client::ControlPlaneClient;

use fleetos_agent::client::watch::watch_sag;
use fleetos_agent::identity::keystore::{SensitiveStore, TpmSealedStore};
use fleetos_agent::identity::svid::SvidState;
use fleetos_agent::storage::Storage;
use fleetos_core::proto::fleetos::{
    SagUpdate, WatchRequest,
    policy_service_server::{PolicyService, PolicyServiceServer},
};
use futures::{Stream, StreamExt, pin_mut};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

pub mod common;

struct MockPolicyService {
    call_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl PolicyService for MockPolicyService {
    type WatchSagStream = Pin<Box<dyn Stream<Item = Result<SagUpdate, Status>> + Send>>;

    async fn watch_sag(
        &self,
        _request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchSagStream>, Status> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst);
        let stream = async_stream::stream! {
            match count {
                0 => {
                    yield Ok(SagUpdate { version: 1, rules: vec![], revoked_spiffe_ids: vec![], revoked_delegation_ids: vec![] });
                    // Stream ends here, simulating server closing connection
                }
                1 => {
                    yield Ok(SagUpdate { version: 2, rules: vec![], revoked_spiffe_ids: vec![], revoked_delegation_ids: vec![] });
                }
                2 => {
                    // Send a stale frame (version 1), then a new frame (version 3)
                    yield Ok(SagUpdate { version: 1, rules: vec![], revoked_spiffe_ids: vec![], revoked_delegation_ids: vec![] });
                    yield Ok(SagUpdate { version: 3, rules: vec![], revoked_spiffe_ids: vec![], revoked_delegation_ids: vec![] });
                }
                _ => {
                    // Keep connection open but yield nothing to let the test finish
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}

#[tokio::test]
async fn watch_reconnect_and_monotonicity() {
    // Install the rustls crypto provider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = TestCa::generate().expect("test CA");
    let (server_cert_pem, server_key_pem) = ca.server_identity().expect("server identity");
    let ca_pem = ca.cert_pem();
    let identity = Identity::from_pem(&server_cert_pem, &server_key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);

    let call_count = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(MockPolicyService {
        call_count: call_count.clone(),
    });

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(PolicyServiceServer::from_arc(mock))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // Setup client with dummy SVID
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp_dir.path()).unwrap());
    let keystore = Arc::new(TpmSealedStore::new(None));

    let svid_params = rcgen::CertificateParams::new(vec!["dummy".to_string()]).unwrap();
    let svid_key = rcgen::KeyPair::generate().unwrap();
    let svid_cert = svid_params.self_signed(&svid_key).unwrap();

    let svid_state = SvidState {
        cert_chain_der: vec![svid_cert.der().to_vec()],
        svid_version: 1,
        generation: 1,
    };

    keystore.generate_and_store_sealing_key(&storage).unwrap();
    // Store the dummy SVID private key so get_channel succeeds
    keystore
        .store_sealed(&storage, b"svid_private_key", &svid_key.serialize_der())
        .unwrap();

    let client = Arc::new(ControlPlaneClient::new(
        addr.to_string(),
        storage,
        keystore,
        Arc::new(ca_pem),
        Arc::new(RwLock::new(svid_state)),
    ));

    let stream = watch_sag(client);
    pin_mut!(stream);
    let mut versions = vec![];

    // Collect the first 3 successful updates
    while let Some(result) = stream.next().await {
        if let Ok(update) = result {
            versions.push(update.version);
            if versions.len() == 3 {
                break;
            }
        }
    }

    // The stale version 1 from the 3rd connection should be discarded
    assert_eq!(versions, vec![1, 2, 3]);
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
}
