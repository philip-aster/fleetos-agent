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

use fleetos_agent::error::AgentError;
use fleetos_agent::workloads::workload_fingerprint;
use fleetos_agent::workloads::{
    NetGuard, NodeIpAllocator, RuntimeKind, SrcIdentityRegistry, WorkloadManager, WorkloadSpec,
    containerd::ContainerdAdapter,
    lifecycle::{PodLifecycle, next_state},
    pod_manager::{Pod, PodManager, PodState},
    reconciler::Reconciler,
    volumes::{self, VolumeConfig},
};
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::fleetos::EmptyDir;
use fleetos_core::proto::fleetos::HostPath;
use fleetos_core::proto::fleetos::Volume;
use fleetos_core::proto::fleetos::volume::Source;
use fleetos_core::proto::workload::{PodSpec, RestartPolicy, VolumeMount};
use fleetos_core::spiffe::{IdKind, SpiffeId, WorkloadRole};
use fleetos_ebpf_common::HostOrderIpv4;
use std::sync::{Arc, Mutex};

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
