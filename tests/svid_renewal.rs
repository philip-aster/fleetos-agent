// SPDX-License-Identifier: Apache-2.0
//! Phase 8.4.6: Node SVID renewal loop tests.
//!
//! Tests the renewal timing computation and the renewal cycle against a
//! mock CaService. The full renewal cycle (keygen → CSR → SubmitCsr →
//! seal → persist → generation bump) is exercised end-to-end.
mod common;
use common::certs::TestCa;
use fleetos_agent::client::ControlPlaneClient;
use fleetos_agent::identity::keystore::{SensitiveStore, TpmSealedStore};
use fleetos_agent::identity::renewal::{RenewalConfig, SvidRenewalLoop};
use fleetos_agent::identity::svid;
use fleetos_agent::storage::Storage;
use fleetos_core::spiffe::{IdKind, SpiffeId};
use std::sync::Arc;
use tokio::sync::RwLock;
// --- Renewal timing tests (pure) ---
#[test]
fn renewal_interval_is_fraction_of_ttl() {
    let config = RenewalConfig {
        ttl_secs: 3600,
        refresh_fraction: 0.75,
    };
    assert_eq!(config.renewal_interval().as_secs(), 2700); // 45 min
}
#[test]
fn renewal_interval_floors_at_60_seconds() {
    let config = RenewalConfig {
        ttl_secs: 10,
        refresh_fraction: 0.5,
    };
    // 10 * 0.5 = 5, floored to 60.
    assert_eq!(config.renewal_interval().as_secs(), 60);
}
#[test]
fn renewal_interval_with_custom_fraction() {
    let config = RenewalConfig {
        ttl_secs: 7200,
        refresh_fraction: 0.5,
    };
    assert_eq!(config.renewal_interval().as_secs(), 3600);
}
// --- Full renewal cycle integration test ---
#[tokio::test]
async fn renewal_cycle_updates_svid_state() {
    // Install the rustls crypto provider.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca = TestCa::generate().expect("test CA");
    let (server_cert_pem, server_key_pem) = ca.server_identity().expect("server identity");
    let ca_pem = ca.cert_pem();
    // Spawn a mock CaService that signs CSRs.
    // Move `ca` into the server — no clone needed.
    let (addr, _call_count) = spawn_ca_server(&server_cert_pem, &server_key_pem, ca).await;
    // Set up storage + keystore + initial SVID.
    let temp_dir = tempfile::tempdir().unwrap();
    let storage = Arc::new(Storage::open(temp_dir.path()).unwrap());
    let keystore = Arc::new(TpmSealedStore::new(None)); // software sealing
    // Generate and store an initial SVID (simulating post-join state).
    let initial_key = rcgen::KeyPair::generate().unwrap();
    let initial_params = rcgen::CertificateParams::new(vec!["initial".to_string()]).unwrap();
    let initial_cert = initial_params.self_signed(&initial_key).unwrap();
    keystore
        .store_sealed(&storage, b"svid_private_key", &initial_key.serialize_der())
        .unwrap();
    let initial_state = svid::store(
        &storage,
        &[initial_cert.der().to_vec()],
        1, // svid_version
        0, // generation
    )
    .unwrap();
    let svid_state = Arc::new(RwLock::new(initial_state));
    // Build the control client.
    let trust_bundle = Arc::new(RwLock::new(ca_pem));
    let client = Arc::new(ControlPlaneClient::new(
        addr,
        storage.clone(),
        keystore.clone(),
        trust_bundle,
        svid_state.clone(),
    ));
    // Build the renewal loop.
    let node_spiffe_id = SpiffeId::new("fleet.test.internal", "system", IdKind::Node, "test-node");
    let renewal_config = RenewalConfig {
        ttl_secs: 3600,
        refresh_fraction: 0.75,
    };
    let renewal_loop = SvidRenewalLoop::new(
        client,
        keystore.clone(),
        storage.clone(),
        svid_state.clone(),
        node_spiffe_id,
        renewal_config,
    );
    // Perform a single renewal (not the loop — just the renew() method).
    renewal_loop.renew().await.expect("renewal should succeed");
    // Verify the SVID state was updated.
    let state = svid_state.read().await;
    assert_eq!(state.svid_version, 2, "svid_version must be bumped");
    assert_eq!(state.generation, 2, "generation must be bumped");
    assert!(
        !state.cert_chain_der.is_empty(),
        "cert chain must be present"
    );

    // Verify the persisted state matches.
    let persisted = svid::load(&storage).unwrap();
    assert_eq!(persisted.svid_version, 2);
    assert_eq!(persisted.generation, 2);
    // Verify the private key was re-sealed (loadable).
    let loaded_key = keystore.load_sealed(&storage, b"svid_private_key").unwrap();
    assert!(loaded_key.is_some(), "new private key must be sealed");
}
// --- Mock CaService for renewal tests ---
use fleetos_core::proto::fleetos::{
    CsrRequest, SvidResponse,
    ca_service_server::{CaService, CaServiceServer},
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
struct MockCaService {
    ca: TestCa,
    call_count: Arc<AtomicUsize>,
}
#[tonic::async_trait]
impl CaService for MockCaService {
    async fn submit_csr(
        &self,
        request: Request<CsrRequest>,
    ) -> Result<Response<SvidResponse>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let csr_der = request.into_inner().csr_der;
        let cert_der = self
            .ca
            .sign_csr(&csr_der, 3600)
            .map_err(|e| Status::internal(format!("CSR signing failed: {}", e)))?;
        Ok(Response::new(SvidResponse {
            cert_chain_der: cert_der,
            keypair_der: Vec::new(), // Node keeps its own key (CR-10).
            svid_version: 2,         // Bumped from initial version 1.
        }))
    }
    async fn get_trust_bundle(
        &self,
        _request: Request<fleetos_core::proto::fleetos::TrustBundleRequest>,
    ) -> Result<Response<fleetos_core::proto::fleetos::TrustBundle>, Status> {
        Ok(Response::new(fleetos_core::proto::fleetos::TrustBundle {
            trust_domain: "fleet.test.internal".to_string(),
            roots_der: vec![self.ca.cert_der()],
        }))
    }
}
async fn spawn_ca_server(
    server_cert_pem: &str,
    server_key_pem: &str,
    ca: TestCa,
) -> (String, Arc<AtomicUsize>) {
    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let tls = ServerTlsConfig::new().identity(identity);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let call_count = Arc::new(AtomicUsize::new(0));
    let mock = Arc::new(MockCaService {
        ca,
        call_count: call_count.clone(),
    });
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(CaServiceServer::from_arc(mock))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr.to_string(), call_count)
}
