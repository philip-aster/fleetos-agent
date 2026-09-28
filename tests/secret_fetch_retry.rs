// SPDX-License-Identifier: Apache-2.0
//! Integration test: Secret fetch with redirect-and-retry (Phase 6.3).

use common::certs::TestCa;
use fleetos_agent::client::ControlPlaneClient;
use fleetos_agent::client::unary::fetch_secret;
use fleetos_agent::identity::keystore::{SensitiveStore, TpmSealedStore};
use fleetos_agent::identity::svid::SvidState;
use fleetos_agent::storage::Storage;
use fleetos_core::proto::fleetos::{
    FetchSecretRequest, SealedSecret,
    secret_service_server::{SecretService, SecretServiceServer},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

pub mod common;

struct MockSecretService {
    call_count: Arc<AtomicUsize>,
    leader_addr: Option<String>,
}

#[tonic::async_trait]
impl SecretService for MockSecretService {
    async fn fetch_secret(
        &self,
        _request: Request<FetchSecretRequest>,
    ) -> Result<Response<SealedSecret>, Status> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
            if let Some(leader) = &self.leader_addr {
                let mut status = Status::unavailable("not leader");
                status
                    .metadata_mut()
                    .insert("leader-dc-address", leader.parse().unwrap());
                return Err(status);
            }
        }

        Ok(Response::new(SealedSecret {
            target_spiffe_id: "test".to_string(),
            sealed_for_svid_version: 1,
            sequence: 1,
            ephemeral_pubkey: vec![0; 32],
            ciphertext: vec![1, 2, 3],
        }))
    }
}

async fn spawn_server(
    leader_addr: Option<String>,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> (String, Arc<AtomicUsize>) {
    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);

    let call_count = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(MockSecretService {
        call_count: call_count.clone(),
        leader_addr,
    });

    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(SecretServiceServer::from_arc(mock))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    (addr.to_string(), call_count)
}

#[tokio::test]
async fn secret_fetch_redirect_and_retry() {
    // Install the rustls crypto provider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = TestCa::generate().expect("test CA");
    let (cert_a, key_a) = ca.server_identity().expect("server identity A");
    let (cert_b, key_b) = ca.server_identity().expect("server identity B");
    let ca_pem = ca.cert_pem();

    // Spawn Server B (the leader), then Server A (redirects to B).
    let (addr_b, count_b) = spawn_server(None, &cert_b, &key_b).await;
    let (addr_a, count_a) = spawn_server(Some(addr_b.clone()), &cert_a, &key_a).await;

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
    keystore
        .store_sealed(&storage, b"svid_private_key", &svid_key.serialize_der())
        .unwrap();

    let client = Arc::new(ControlPlaneClient::new(
        addr_a.clone(), // Initially target Server A
        storage,
        keystore,
        Arc::new(ca_pem),
        Arc::new(RwLock::new(svid_state)),
    ));

    // Execute fetch
    let result = fetch_secret(&client, "spiffe://test", 1).await;

    // Verify success
    assert!(
        result.is_ok(),
        "fetch_secret should succeed after redirect: {:?}",
        result.err()
    );
    let secret = result.unwrap();
    assert_eq!(secret.ciphertext, vec![1, 2, 3]);

    // Verify Server A was hit once (and redirected)
    assert_eq!(count_a.load(Ordering::SeqCst), 1);

    // Verify Server B was hit once (and succeeded)
    assert_eq!(count_b.load(Ordering::SeqCst), 1);

    // Verify the client retargeted internally
    let current_target = client.current_target().await;
    assert_eq!(current_target, addr_b);
}
