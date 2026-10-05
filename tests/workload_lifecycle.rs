// SPDX-License-Identifier: Apache-2.0
//! Phase 6.5 — Workload boot/stop lifecycle.
//!
//! Covers the orchestration layer without real containerd/Cloud Hypervisor:
//! - Reconciler boot/evict decisions (pure)
//! - Pod lifecycle restart policy state machine (pure)
//! - Volume prep: EmptyDir creation, HostPath default-deny, undefined-volume reject
//! - Boot-race guard (Rule #7 / flagged item): NetGuard::arm BEFORE adapter boot,
//!   fail-closed when guard is absent or arm fails
//! - Containerd path does NOT arm NetGuard (by design: connect4, not TC)
//!
//! Actual containerd/Cloud Hypervisor boot execution requires real runtimes
//! and is covered by SDK verification points; this file tests orchestration.

mod common;
use fleetos_agent::client::ControlPlaneClient;
use fleetos_agent::error::AgentError;
use fleetos_agent::identity::degraded::DelegatedKeyManager;
use fleetos_agent::identity::keystore::{SensitiveStore, TpmSealedStore};
use fleetos_agent::identity::svid::SvidState;
use fleetos_agent::storage::Storage;
use fleetos_agent::wiring::{mark_all_pods_policy_enforced, reevaluate_router_connected};
use fleetos_agent::workloads::{
    NetGuard, NodeIpAllocator, RuntimeKind, SrcIdentityRegistry, WorkloadManager, WorkloadSpec,
    containerd::ContainerdAdapter,
    lifecycle::{PodLifecycle, next_state},
    pod_manager::{Pod, PodManager, PodState},
    reconciler::Reconciler,
    volumes::{self, VolumeConfig},
    workload_fingerprint,
};
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::fleetos::volume::Source;
use fleetos_core::proto::fleetos::{
    DelegatedKeyRequest, DelegatedKeyResponse,
    delegation_service_server::{DelegationService, DelegationServiceServer},
};
use fleetos_core::proto::fleetos::{EmptyDir, HostPath, Volume};
use fleetos_core::proto::state::RouteEntry;
use fleetos_core::proto::workload::{PodSpec, RestartPolicy, VolumeMount};
use fleetos_core::spiffe::{IdKind, SpiffeId, WorkloadRole};
use fleetos_ebpf_common::HostOrderIpv4;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

// --- Mock NetGuard: records arm() calls, optionally fails arm ---
struct MockNetGuard {
    armed: Mutex<Vec<String>>,
    fail_arm: bool,
}
impl MockNetGuard {
    fn new(fail_arm: bool) -> Self {
        Self {
            armed: Mutex::new(Vec::new()),
            fail_arm,
        }
    }
    fn armed_interfaces(&self) -> Vec<String> {
        self.armed.lock().unwrap().clone()
    }
}
impl NetGuard for MockNetGuard {
    fn arm(&self, interface: &str) -> Result<(), AgentError> {
        if self.fail_arm {
            return Err(AgentError::Workload("mock arm failure".into()));
        }
        self.armed.lock().unwrap().push(interface.to_string());
        Ok(())
    }
    fn disarm(&self, _interface: &str) -> Result<(), AgentError> {
        Ok(())
    }
}

// =========================================================================
// Boot-path delegation (Phase 7.5) — mock ControlPlaneClient integration
// =========================================================================
//
// Verifies that boot_pod requests and installs a delegated signing key via
// the real request_and_install path against a mock DelegationService. Boot
// itself fails (no runtime), but the delegation request completes first.

/// Serializable mirror of DelegatedSigningKeyWire (which is Deserialize-only).
/// Field order must match exactly — postcard is positional.
#[derive(serde::Serialize)]
struct DelegationKeyWire {
    node_id: SpiffeId,
    target_svid_id: SpiffeId,
    target_ordinal: Option<u32>,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signing_key: Vec<u8>,
    intermediate_cert_der: Vec<u8>,
    target_role: Option<WorkloadRole>,
}

/// Build a valid postcard-encoded DelegatedSigningKey for the given target.
fn build_key_material(target: &SpiffeId, role: &str, ordinal: Option<u32>) -> Vec<u8> {
    let int_key = rcgen::KeyPair::generate().unwrap();
    let mut int_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Test Delegated Intermediate");
    int_params.distinguished_name = dn;
    int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    int_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let int_cert = int_params.self_signed(&int_key).unwrap();
    let now = fleetos_agent::identity::degraded::now_unix();
    let wire = DelegationKeyWire {
        node_id: "spiffe://test.internal/ns/system/node/agent-1"
            .parse()
            .unwrap(),
        target_svid_id: target.clone(),
        target_ordinal: ordinal,
        issued_at_unix: now,
        expires_at_unix: now + 14400,
        signing_key: int_key.serialize_der(),
        intermediate_cert_der: int_cert.der().to_vec(),
        target_role: Some(WorkloadRole::try_from(role).unwrap()),
    };
    postcard::to_allocvec(&wire).unwrap()
}

/// Mock DelegationService: captures the request, returns a valid key.
struct MockDelegationService {
    key_material: Vec<u8>,
    last_request: std::sync::Mutex<Option<DelegatedKeyRequest>>,
    call_count: AtomicUsize,
}

#[tonic::async_trait]
impl DelegationService for MockDelegationService {
    async fn request_delegated_key(
        &self,
        request: Request<DelegatedKeyRequest>,
    ) -> Result<Response<DelegatedKeyResponse>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        *self.last_request.lock().unwrap() = Some(request.into_inner());
        Ok(Response::new(DelegatedKeyResponse {
            delegation_id: b"test-delegation-id".to_vec(),
            key_material: self.key_material.clone(),
            expires_at_unix: fleetos_agent::identity::degraded::now_unix() + 14400,
        }))
    }
}

/// Spawn a mock DelegationService behind TLS. Returns (address, service handle).
async fn spawn_delegation_server(
    key_material: Vec<u8>,
    server_cert_pem: &str,
    server_key_pem: &str,
) -> (String, Arc<MockDelegationService>) {
    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let tls = ServerTlsConfig::new().identity(identity);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = TcpListenerStream::new(listener);
    let service = Arc::new(MockDelegationService {
        key_material,
        last_request: std::sync::Mutex::new(None),
        call_count: AtomicUsize::new(0),
    });
    let svc = service.clone();
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(DelegationServiceServer::from_arc(svc))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr.to_string(), service)
}

#[tokio::test]
async fn boot_pod_requests_and_installs_delegated_key() {
    // FIX: Install the rustls crypto provider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    // --- TLS material (same pattern as secret_fetch_retry.rs) ---
    let ca = common::certs::TestCa::generate().unwrap();
    let (server_cert_pem, server_key_pem) = ca.server_identity().unwrap();
    let ca_pem = ca.cert_pem();

    // The workload we'll boot.
    let spec = make_spec("web", RuntimeKind::CloudHypervisor);
    let expected_target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/web".parse().unwrap();

    // Build valid key material for this target.
    let key_material = build_key_material(&expected_target, "primary", None);

    // Spawn mock DelegationService.
    let (addr, mock_svc) =
        spawn_delegation_server(key_material, &server_cert_pem, &server_key_pem).await;

    // --- ControlPlaneClient with a dummy SVID ---
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
        addr,
        storage,
        keystore,
        Arc::new(ca_pem),
        Arc::new(tokio::sync::RwLock::new(svid_state)),
    ));

    // --- WorkloadManager with delegation ---
    let delegated_keys = Arc::new(std::sync::RwLock::new(DelegatedKeyManager::new()));
    let node_spiffe: SpiffeId = "spiffe://test.internal/ns/system/node/agent-1"
        .parse()
        .unwrap();

    let containerd = Arc::new(ContainerdAdapter::new_lazy("fleetos", String::new()));
    let tempdir = tempfile::tempdir().unwrap();
    let volume_config = VolumeConfig {
        scratch_root: tempdir.path().to_path_buf(),
        allow_host_path: false,
    };
    let pod_manager = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    let ip_alloc = Arc::new(std::sync::Mutex::new(
        NodeIpAllocator::new("172.30.0.0/16").unwrap(),
    ));
    let wm = WorkloadManager::new(
        containerd,
        volume_config,
        pod_manager.clone(),
        None, // no NetGuard
        "test.internal".to_string(),
        None, // no SrcIdentityRegistry
        ip_alloc,
    )
    .with_delegation(client, delegated_keys.clone(), node_spiffe, 14400);

    // --- Reconcile: triggers boot_pod which requests the delegated key ---
    wm.reconcile(&[spec]).await.unwrap();

    // --- Assertions ---

    // 1. The mock was called exactly once.
    assert_eq!(
        mock_svc.call_count.load(Ordering::SeqCst),
        1,
        "DelegationService must be called exactly once"
    );

    // 2. The request carried the correct target SPIFFE ID and node SVID.
    let captured = mock_svc.last_request.lock().unwrap().take().unwrap();
    assert_eq!(
        captured.target_spiffe_id, "spiffe://test.internal/ns/tenant-1/sa/web",
        "target_spiffe_id must match the workload identity"
    );
    assert_eq!(
        captured.node_svid, "spiffe://test.internal/ns/system/node/agent-1",
        "node_svid must be the agent's node identity"
    );

    // 3. The key was installed in the DelegatedKeyManager.
    let mgr = delegated_keys.read().unwrap();
    let now = fleetos_agent::identity::degraded::now_unix();
    assert!(
        mgr.has_valid_key(&expected_target, now),
        "delegated key must be installed after boot_pod"
    );

    // 4. The key can be retrieved and has the right target.
    let key = mgr.get_key(&expected_target, now);
    assert!(key.is_some(), "key must be retrievable");
    let key = key.unwrap();
    assert_eq!(key.target_svid_id, expected_target);
    assert_eq!(
        key.target_role,
        Some(WorkloadRole::try_from("primary").unwrap())
    );

    // 5. Boot itself failed (no real runtime), so no pod is registered.
    drop(mgr);
    let pm = pod_manager.read().await;
    assert!(
        pm.is_empty(),
        "boot fails without a real runtime; no pod registered"
    );
}

fn make_spec(workload_id: &str, runtime: RuntimeKind) -> WorkloadSpec {
    let pod_spec = PodSpec {
        pod_id: Some(format!("{}-pod", workload_id)),
        tenant_id: "tenant-1".to_string(),
        workload_id: workload_id.to_string(),
        role: "primary".to_string(),
        image: "test-image".to_string(),
        volumes: vec![],
        volume_mounts: vec![],
        ..Default::default()
    };
    WorkloadSpec {
        workload_id: workload_id.to_string(),
        runtime,
        image: "test-image".to_string(),
        role: "primary".to_string(),
        pod_spec: Some(pod_spec),
        hostname: format!("{}.primary.tenant-1.svc.test.internal", workload_id),
    }
}

fn make_manager_parts(
    tempdir: &tempfile::TempDir,
    net_guard: Option<Arc<dyn NetGuard>>,
) -> (WorkloadManager, Arc<tokio::sync::RwLock<PodManager>>) {
    let containerd = Arc::new(ContainerdAdapter::new_lazy("fleetos", String::new()));
    let volume_config = VolumeConfig {
        scratch_root: tempdir.path().to_path_buf(),
        allow_host_path: false,
    };
    let pod_manager = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    let ip_allocator = Arc::new(std::sync::Mutex::new(
        NodeIpAllocator::new("172.30.0.0/16").unwrap(),
    ));
    let wm = WorkloadManager::new(
        containerd,
        volume_config,
        pod_manager.clone(),
        net_guard,
        "test.internal".to_string(),
        None,
        ip_allocator,
    );
    (wm, pod_manager)
}

#[derive(Default)]
struct MockSrcIdentityRegistry {
    registered: std::sync::Mutex<Vec<(u32, IdentityFingerprint)>>,
    unregistered: std::sync::Mutex<Vec<u32>>,
}
impl SrcIdentityRegistry for MockSrcIdentityRegistry {
    fn register(&self, ip: HostOrderIpv4, fp: &IdentityFingerprint) -> Result<(), AgentError> {
        self.registered.lock().unwrap().push((ip.0, *fp));
        Ok(())
    }
    fn unregister(&self, ip: HostOrderIpv4) -> Result<(), AgentError> {
        self.unregistered.lock().unwrap().push(ip.0);
        Ok(())
    }
}

fn make_ready_pod(pod_id: &str, workload_id: &str, tenant_id: &str) -> Pod {
    Pod::new(
        pod_id.into(),
        workload_id.into(),
        tenant_id.into(),
        "primary".into(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([7; 16]),
    )
}

#[tokio::test]
async fn route_update_sets_router_connected_for_pods_with_routed_deps() {
    // "web" calls "db": web appears in the db route's source_spiffe_ids.
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_ready_pod("web-pod", "web", "tenant-1"));
    pm.write()
        .await
        .add_pod(make_ready_pod("db-pod", "db", "tenant-1"));

    let routes = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0xF000_0001, // routed (non-zero)
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    }];

    reevaluate_router_connected(&pm, &routes, "test.internal").await;

    let pm = pm.read().await;
    // web depends on db, and db is routed -> web is connected.
    assert!(pm.get_pod("web-pod").unwrap().router_connected);
    // db has no outbound deps -> trivially connected.
    assert!(pm.get_pod("db-pod").unwrap().router_connected);
}

#[tokio::test]
async fn route_removal_flips_router_connected_false() {
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_ready_pod("web-pod", "web", "tenant-1"));

    // web depends on db; db is routed.
    let with_route = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0xF000_0001,
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    }];
    reevaluate_router_connected(&pm, &with_route, "test.internal").await;
    assert!(pm.read().await.get_pod("web-pod").unwrap().router_connected);

    // db's route becomes unrouted (dummy_ip = 0 sentinel) -> web flips to false.
    let unrouted = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0, // unrouted sentinel
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    }];
    reevaluate_router_connected(&pm, &unrouted, "test.internal").await;
    assert!(!pm.read().await.get_pod("web-pod").unwrap().router_connected);
}

#[tokio::test]
async fn policy_sync_sets_policy_enforced_on_all_pods() {
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_ready_pod("web-pod", "web", "tenant-1"));
    pm.write()
        .await
        .add_pod(make_ready_pod("db-pod", "db", "tenant-1"));

    mark_all_pods_policy_enforced(&pm).await;

    let pm = pm.read().await;
    assert!(pm.get_pod("web-pod").unwrap().policy_enforced);
    assert!(pm.get_pod("db-pod").unwrap().policy_enforced);
}

#[test]
fn node_ip_allocator_allocates_reuses_and_rejects_dummy_space() {
    let mut a = NodeIpAllocator::new("172.30.0.0/24").unwrap();
    let x = a.allocate("p1").unwrap();
    let y = a.allocate("p2").unwrap();
    assert_ne!(x, y);
    assert_eq!(x, 0xAC1E0001); // 172.30.0.1
    a.release("p1");
    assert_eq!(a.allocate("p3").unwrap(), x); // reused
    assert!(NodeIpAllocator::new("240.0.0.0/24").is_err()); // dummy space rejected
}

#[test]
fn mark_started_sets_started_and_gate_term() {
    let mut pod = Pod::new(
        "web-pod".into(),
        "web".into(),
        "tenant-1".into(),
        "primary".into(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([7; 16]),
    );
    // Freshly created: not started, gate cannot pass.
    assert!(!pod.started);
    assert!(!pod.can_transition_to_running());

    // Boot confirmed -> started set.
    pod.mark_started();
    assert!(pod.started);

    // Still not Running until policy + router are also set.
    assert!(!pod.can_transition_to_running());
    pod.mark_policy_enforced();
    pod.mark_router_connected();
    assert!(
        pod.can_transition_to_running(),
        "gate passes once started + policy_enforced + router_connected"
    );
}

// --- CORE-WI-5 regression tests ---

/// No outbound dependencies -> trivially connected.
#[tokio::test]
async fn pod_with_no_outbound_deps_is_trivially_connected() {
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_ready_pod("lonely-pod", "lonely", "tenant-1"));

    // Route set exists but "lonely" appears in no source_spiffe_ids.
    let routes = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0xF000_0001,
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/other".to_string()],
    }];
    reevaluate_router_connected(&pm, &routes, "test.internal").await;
    assert!(
        pm.read()
            .await
            .get_pod("lonely-pod")
            .unwrap()
            .router_connected
    );

    // Also true with an empty route set.
    reevaluate_router_connected(&pm, &[], "test.internal").await;
    assert!(
        pm.read()
            .await
            .get_pod("lonely-pod")
            .unwrap()
            .router_connected
    );
}

/// Dependencies unrouted (dummy_ip = 0) -> disconnected.
#[tokio::test]
async fn pod_with_unrouted_deps_is_disconnected() {
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_ready_pod("web-pod", "web", "tenant-1"));

    let routes = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0, // unrouted sentinel
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    }];
    reevaluate_router_connected(&pm, &routes, "test.internal").await;
    assert!(!pm.read().await.get_pod("web-pod").unwrap().router_connected);
}

/// Regression: pure-client pod (calls others, never called) must NOT be stuck
/// disconnected. It has outbound deps; once they're routed it's connected.
#[tokio::test]
async fn pure_client_pod_not_stuck_disconnected() {
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    // "client" only calls "db"; it is never a destination itself.
    pm.write()
        .await
        .add_pod(make_ready_pod("client-pod", "client", "tenant-1"));

    let routes = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0xF000_0001,
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/client".to_string()],
    }];
    reevaluate_router_connected(&pm, &routes, "test.internal").await;
    assert!(
        pm.read()
            .await
            .get_pod("client-pod")
            .unwrap()
            .router_connected,
        "pure-client pod must not be stuck disconnected"
    );
}

/// Regression: server-only pod (called, never calls) must NOT be connected
/// trivially via destination matching. It has no outbound deps, so it's
/// connected only because it has nothing to depend on — NOT because it's a
/// destination. Verify the logic doesn't key off destination.
#[tokio::test]
async fn server_only_pod_not_trivially_connected_via_destination() {
    let pm = Arc::new(tokio::sync::RwLock::new(PodManager::new()));
    // "db" is only ever a destination, never a source.
    pm.write()
        .await
        .add_pod(make_ready_pod("db-pod", "db", "tenant-1"));

    // db appears as a destination but NOT in any source_spiffe_ids.
    let routes = vec![RouteEntry {
        destination_svid: "spiffe://test.internal/ns/tenant-1/sa/db".to_string(),
        destination_role: "primary".to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip: 0xF000_0001,
        source_spiffe_ids: vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    }];
    reevaluate_router_connected(&pm, &routes, "test.internal").await;
    // db has no outbound deps -> connected=true, but because it has no deps,
    // NOT because it's a destination. (Under the old destination-based logic,
    // this would also be true, but for the wrong reason; this test documents
    // that the value is correct and the new logic doesn't depend on destination.)
    assert!(pm.read().await.get_pod("db-pod").unwrap().router_connected);
}

#[tokio::test]
async fn boot_microvm_registers_src_identity_and_cleans_up_on_failure() {
    let tempdir = tempfile::tempdir().unwrap();
    let registry = Arc::new(MockSrcIdentityRegistry::default());
    let ip_alloc = Arc::new(std::sync::Mutex::new(
        NodeIpAllocator::new("172.30.0.0/16").unwrap(),
    ));
    let wm = WorkloadManager::new(
        Arc::new(ContainerdAdapter::new_lazy("fleetos", String::new())),
        VolumeConfig {
            scratch_root: tempdir.path().to_path_buf(),
            allow_host_path: false,
        },
        Arc::new(tokio::sync::RwLock::new(PodManager::new())),
        Some(Arc::new(MockNetGuard::new(false))),
        "test.internal".to_string(),
        Some(registry.clone()),
        ip_alloc.clone(),
    );
    let spec = make_spec("web", RuntimeKind::CloudHypervisor);
    wm.reconcile(&[spec]).await.unwrap(); // boot fails (no CH); reconcile swallows
    let reg = registry.registered.lock().unwrap();
    assert_eq!(reg.len(), 1, "registered before boot");
    assert_ne!(
        reg[0].1,
        IdentityFingerprint([0; 16]),
        "real fingerprint, not zero"
    );
    assert_eq!(
        registry.unregistered.lock().unwrap().len(),
        1,
        "unregistered on boot failure"
    );
    assert_eq!(
        ip_alloc.lock().unwrap().allocated_count(),
        0,
        "IP released on failure"
    );
}

// =========================================================================
// Reconciler boot/evict decisions (pure)
// =========================================================================
#[test]
fn reconciler_boots_missing_and_evicts_absent() {
    let mut pm = PodManager::new();
    let mut running = Pod::new(
        "web-pod".into(),
        "web".into(),
        "t".into(),
        "primary".into(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([0; 16]),
    );
    running.state = PodState::Running;
    pm.add_pod(running);

    let desired = vec![make_spec("api", RuntimeKind::CloudHypervisor)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");

    assert_eq!(result.to_boot.len(), 1, "api must be booted");
    assert_eq!(result.to_boot[0].workload_id, "api");
    assert_eq!(
        result.to_evict,
        vec!["web-pod".to_string()],
        "web must be evicted"
    );
}

#[test]
fn reconciler_noop_when_desired_matches_running() {
    let mut pm = PodManager::new();
    let mut running = Pod::new(
        "web-pod".into(),
        "web".into(),
        "t".into(),
        "primary".into(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([0; 16]),
    );
    running.state = PodState::Running;
    pm.add_pod(running);

    let desired = vec![make_spec("web", RuntimeKind::CloudHypervisor)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    assert!(
        result.is_empty(),
        "no boot/evict when desired matches running"
    );
}

// =========================================================================
// Pod lifecycle restart policy state machine (pure)
// =========================================================================
#[test]
fn lifecycle_never_policy_never_restarts() {
    let lc = PodLifecycle::new(RestartPolicy::Never, 30);
    assert!(!lc.can_restart());
}

#[test]
fn lifecycle_always_restarts_until_max() {
    let mut lc = PodLifecycle::new(RestartPolicy::Always, 30);
    assert!(lc.can_restart());
    assert!(lc.record_restart(), "restart 1 allowed");
    assert!(lc.record_restart(), "restart 2 allowed");
    assert!(lc.record_restart(), "restart 3 allowed");
    assert!(!lc.record_restart(), "restart 4 exceeds max_restarts");
}

#[test]
fn next_state_failed_pod_restarts_or_stops_per_policy() {
    let mut lc_always = PodLifecycle::new(RestartPolicy::Always, 30);
    assert_eq!(
        next_state(PodState::Running, true, &mut lc_always),
        PodState::Booting
    );

    let mut lc_never = PodLifecycle::new(RestartPolicy::Never, 30);
    assert_eq!(
        next_state(PodState::Running, true, &mut lc_never),
        PodState::Stopped
    );

    // Non-failed running pod stays put.
    let mut lc = PodLifecycle::new(RestartPolicy::Always, 30);
    assert_eq!(
        next_state(PodState::Running, false, &mut lc),
        PodState::Running
    );
}

// =========================================================================
// Volume preparation (fs + tempdir)
// =========================================================================
#[tokio::test]
async fn emptydir_volume_created_per_pod() {
    let tempdir = tempfile::tempdir().unwrap();
    let config = VolumeConfig {
        scratch_root: tempdir.path().to_path_buf(),
        allow_host_path: false,
    };
    let volumes = vec![Volume {
        name: "scratch".to_string(),
        source: Some(Source::EmptyDir(EmptyDir {
            size_limit_bytes: None,
        })),
    }];
    let mounts = vec![VolumeMount {
        name: "scratch".to_string(),
        mount_path: "/scratch".to_string(),
        read_only: false,
    }];

    let prepared = volumes::prepare_mounts(&config, "pod-1", &volumes, &mounts).unwrap();
    assert_eq!(prepared.len(), 1);
    assert_eq!(prepared[0].name, "scratch");
    assert_eq!(prepared[0].mount_path, "/scratch");
    // EmptyDir created under scratch_root/pod_id/volume_name.
    assert!(tempdir.path().join("pod-1").join("scratch").exists());
}

#[tokio::test]
async fn hostpath_volume_default_deny() {
    let tempdir = tempfile::tempdir().unwrap();
    let config = VolumeConfig {
        scratch_root: tempdir.path().to_path_buf(),
        allow_host_path: false, // default-deny
    };
    let host_path = tempdir.path().join("hostdir");
    std::fs::create_dir_all(&host_path).unwrap();
    let volumes = vec![Volume {
        name: "hostvol".to_string(),
        source: Some(Source::HostPath(HostPath {
            path: host_path.to_string_lossy().to_string(),
            r#type: 1,
        })),
    }];
    let mounts = vec![VolumeMount {
        name: "hostvol".to_string(),
        mount_path: "/host".to_string(),
        read_only: true,
    }];

    let result = volumes::prepare_mounts(&config, "pod-1", &volumes, &mounts);
    assert!(
        result.is_err(),
        "HostPath must be default-denied (zero-trust)"
    );
}

#[tokio::test]
async fn undefined_volume_reference_rejected() {
    let tempdir = tempfile::tempdir().unwrap();
    let config = VolumeConfig {
        scratch_root: tempdir.path().to_path_buf(),
        allow_host_path: false,
    };
    let volumes = vec![]; // no volumes defined
    let mounts = vec![VolumeMount {
        name: "nonexistent".to_string(),
        mount_path: "/data".to_string(),
        read_only: false,
    }];

    let result = volumes::prepare_mounts(&config, "pod-1", &volumes, &mounts);
    assert!(
        result.is_err(),
        "undefined volume reference must be rejected fail-closed"
    );
}

// =========================================================================
// Boot-race guard (Rule #7 / flagged item): arm BEFORE boot, fail-closed
// =========================================================================
#[tokio::test]
async fn boot_microvm_fails_closed_without_net_guard() {
    let tempdir = tempfile::tempdir().unwrap();
    let (wm, pod_manager) = make_manager_parts(&tempdir, None); // no guard

    let spec = make_spec("web", RuntimeKind::CloudHypervisor);
    wm.reconcile(&[spec]).await.unwrap(); // reconcile swallows boot errors

    // Fail-closed: no pod boots without a NetGuard.
    let pm = pod_manager.read().await;
    assert!(
        pm.is_empty(),
        "no pod may boot without a NetGuard (fail-closed)"
    );
}

#[tokio::test]
async fn boot_microvm_arms_net_guard_before_boot() {
    let tempdir = tempfile::tempdir().unwrap();
    let guard = Arc::new(MockNetGuard::new(false));
    let (wm, pod_manager) = make_manager_parts(&tempdir, Some(guard.clone()));

    let spec = make_spec("web", RuntimeKind::CloudHypervisor);
    wm.reconcile(&[spec]).await.unwrap();

    // Ordering invariant: NetGuard::arm was called before the boot attempt.
    let armed = guard.armed_interfaces();
    assert_eq!(armed.len(), 1, "NetGuard::arm must be called before boot");
    assert!(
        armed[0].starts_with("vmtap"),
        "interface must be vmtap{{cid}}"
    );

    // Boot fails without a real Cloud Hypervisor socket, so no pod registers.
    let pm = pod_manager.read().await;
    assert!(
        pm.is_empty(),
        "boot fails without real CH; no pod registered"
    );
}

#[tokio::test]
async fn boot_microvm_aborts_when_arm_fails() {
    let tempdir = tempfile::tempdir().unwrap();
    let guard = Arc::new(MockNetGuard::new(true)); // arm fails
    let (wm, pod_manager) = make_manager_parts(&tempdir, Some(guard.clone()));

    let spec = make_spec("web", RuntimeKind::CloudHypervisor);
    wm.reconcile(&[spec]).await.unwrap();

    // arm was attempted but failed → boot aborts, nothing armed, no pod.
    assert_eq!(
        guard.armed_interfaces().len(),
        0,
        "arm failed, nothing recorded"
    );
    let pm = pod_manager.read().await;
    assert!(
        pm.is_empty(),
        "boot must abort when arm fails (fail-closed)"
    );
}

#[tokio::test]
async fn boot_containerd_does_not_arm_net_guard() {
    let tempdir = tempfile::tempdir().unwrap();
    let guard = Arc::new(MockNetGuard::new(false));
    let (wm, pod_manager) = make_manager_parts(&tempdir, Some(guard.clone()));

    let spec = make_spec("web", RuntimeKind::Containerd); // containerd path
    wm.reconcile(&[spec]).await.unwrap();

    // Containerd enforces via connect4 (node-wide), not TC — NetGuard NOT armed.
    assert_eq!(
        guard.armed_interfaces().len(),
        0,
        "containerd must not arm NetGuard"
    );

    // Boot fails without real containerd; no pod registered.
    let pm = pod_manager.read().await;
    assert!(pm.is_empty());
}

#[test]
fn boot_fingerprint_is_real_and_canonical() {
    let fp = workload_fingerprint("fleet.test.internal", "tenant-1", "web", "primary")
        .expect("fingerprint must compute");
    // 7.6.3: must NOT be the zero placeholder.
    assert_ne!(fp, IdentityFingerprint([0; 16]));
    // Must equal IdentityFingerprint::of computed the same way (Rule #1).
    let spiffe = SpiffeId::new("fleet.test.internal", "tenant-1", IdKind::Sa, "web");
    let role = WorkloadRole::try_from("primary").unwrap();
    assert_eq!(fp, IdentityFingerprint::of(&spiffe, Some(&role)));

    // Deterministic, and role is part of the identity.
    let fp2 = workload_fingerprint("fleet.test.internal", "tenant-1", "web", "primary").unwrap();
    assert_eq!(fp, fp2);
    let fp_replica =
        workload_fingerprint("fleet.test.internal", "tenant-1", "web", "replica").unwrap();
    assert_ne!(fp, fp_replica);
}
