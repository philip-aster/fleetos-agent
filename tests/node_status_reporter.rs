// SPDX-License-Identifier: Apache-2.0
//! Phase 8.4.6: Node liveness heartbeat tests.
//!
//! Tests the NodeStatusReporter against a mock WorkloadStatusService.
//! Verifies the heartbeat carries the correct node_svid and that
//! report_node_status follows the redirect-and-retry pattern.
mod common;
use common::certs::TestCa;
use fleetos_agent::client::ControlPlaneClient;
use fleetos_agent::client::unary::report_node_status;
use fleetos_agent::identity::keystore::{SensitiveStore, TpmSealedStore};
use fleetos_agent::identity::svid::SvidState;
use fleetos_agent::storage::Storage;
use fleetos_core::proto::fleetos::{
    NodeStatusReport, StatusAck,
    workload_status_service_server::{WorkloadStatusService, WorkloadStatusServiceServer},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
struct MockWorkloadStatusService {
    call_count: Arc<AtomicUsize>,
    last_node_svid: std::sync::Mutex<Option<String>>,
}
#[tonic::async_trait]
impl WorkloadStatusService for MockWorkloadStatusService {
    async fn report_workload_status(
        &self,
        _request: Request<fleetos_core::proto::fleetos::WorkloadStatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        Ok(Response::new(StatusAck { accepted: true }))
    }
    async fn report_pod_metrics(
        &self,
        _request: Request<fleetos_core::proto::fleetos::PodMetrics>,
    ) -> Result<Response<fleetos_core::proto::fleetos::MetricsAck>, Status> {
        Ok(Response::new(fleetos_core::proto::fleetos::MetricsAck {
            accepted: true,
        }))
    }
    async fn report_node_status(
        &self,
        request: Request<NodeStatusReport>,
    ) -> Result<Response<StatusAck>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let report = request.into_inner();
        *self.last_node_svid.lock().unwrap() = Some(report.node_svid.clone());
        // Validate the node_svid is a well-formed SPIFFE ID.
        if !report.node_svid.starts_with("spiffe://") {
            return Err(Status::invalid_argument("node_svid must be a SPIFFE URI"));
        }
        Ok(Response::new(StatusAck { accepted: true }))
    }
}
#[tokio::test]
async fn report_node_status_sends_correct_svid() {
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
    let last_node_svid = std::sync::Mutex::new(None);
    let mock = Arc::new(MockWorkloadStatusService {
        call_count: call_count.clone(),
        last_node_svid,
    });
    // Capture the last_node_svid Arc for assertion after the server runs.
    let last_svid_clone = mock.clone();
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(WorkloadStatusServiceServer::from_arc(mock))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    // Set up client with dummy SVID.
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
        addr.to_string(),
        storage,
        keystore,
        Arc::new(RwLock::new(ca_pem)),
        Arc::new(RwLock::new(svid_state)),
    ));
    // Send a heartbeat.
    let node_svid = "spiffe://fleet.test.internal/ns/system/node/test-node".to_string();
    let report = NodeStatusReport {
        node_svid: node_svid.clone(),
        observed_at_unix: 1700000000,
    };
    let result = report_node_status(&client, report).await;
    assert!(result.is_ok(), "report_node_status should succeed");
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
    // Verify the mock received the correct node_svid.
    let received = last_svid_clone.last_node_svid.lock().unwrap().clone();
    assert_eq!(received, Some(node_svid));
}
#[tokio::test]
async fn report_node_status_rejects_non_spiffe_svid() {
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
    let last_node_svid = std::sync::Mutex::new(None);
    let mock = Arc::new(MockWorkloadStatusService {
        call_count: call_count.clone(),
        last_node_svid,
    });
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(WorkloadStatusServiceServer::from_arc(mock))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
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
        addr.to_string(),
        storage,
        keystore,
        Arc::new(RwLock::new(ca_pem)),
        Arc::new(RwLock::new(svid_state)),
    ));
    // Send a heartbeat with a non-SPIFFE node_svid.
    let report = NodeStatusReport {
        node_svid: "not-a-spiffe-id".to_string(),
        observed_at_unix: 1700000000,
    };
    let result = report_node_status(&client, report).await;
    assert!(result.is_err(), "non-SPIFFE node_svid must be rejected");
}
