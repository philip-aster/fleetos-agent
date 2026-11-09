// SPDX-License-Identifier: Apache-2.0
//! Phase 8.6.4: Spec-change replacement tests.
use fleetos_agent::workloads::disruption::{
    DisruptionGuard, DisruptionTarget, FrameConsistencyGuard,
};
use fleetos_agent::workloads::pod_manager::{Pod, PodManager, PodState};
use fleetos_agent::workloads::reconciler::Reconciler;
use fleetos_agent::workloads::{RuntimeKind, WorkloadSpec};
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::workload::{PodSpec, ResourceRequirements};
fn make_pod(pod_id: &str, workload_id: &str, vcpus: u32, memory_bytes: u64) -> Pod {
    let mut pod = Pod::new(
        pod_id.to_string(),
        workload_id.to_string(),
        "tenant-1".to_string(),
        "primary".to_string(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([0u8; 16]),
    );
    pod.state = PodState::Running;
    pod.vcpus = vcpus;
    pod.memory_bytes = memory_bytes;
    pod
}
fn make_spec(pod_id: &str, workload_id: &str, vcpus: u32, memory_mb: u32) -> WorkloadSpec {
    WorkloadSpec {
        workload_id: workload_id.to_string(),
        runtime: RuntimeKind::CloudHypervisor,
        image: "test-image".to_string(),
        role: "primary".to_string(),
        pod_spec: Some(PodSpec {
            pod_id: Some(pod_id.to_string()),
            resources: Some(ResourceRequirements {
                vcpus,
                memory_mb,
                disk_gb: 10,
            }),
            ..Default::default()
        }),
        hostname: format!("{}.test.internal", workload_id),
    }
}
#[test]
fn reconciler_detects_footprint_mismatch() {
    // Running pod has 2 vcpus, 4GB. Frame wants 4 vcpus, 8GB (same pod_id).
    let mut pm = PodManager::new();
    pm.add_pod(make_pod("pod-1", "db", 2, 4096 * 1024 * 1024));
    let desired = vec![make_spec("pod-1", "db", 4, 8192)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    // Footprint mismatch → replacement.
    assert_eq!(result.to_replace.len(), 1);
    assert_eq!(result.to_replace[0].0, "pod-1");
    // No new boot and no eviction.
    assert!(result.to_boot.is_empty());
    assert!(result.to_evict.is_empty());
}
#[test]
fn reconciler_no_action_when_footprint_matches() {
    let mut pm = PodManager::new();
    pm.add_pod(make_pod("pod-1", "db", 2, 4096 * 1024 * 1024));
    let desired = vec![make_spec("pod-1", "db", 2, 4096)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    assert!(result.to_boot.is_empty());
    assert!(result.to_evict.is_empty());
    assert!(result.to_replace.is_empty());
}
#[test]
fn reconciler_evicts_pod_not_in_frame() {
    let mut pm = PodManager::new();
    pm.add_pod(make_pod("pod-1", "db", 2, 4096 * 1024 * 1024));
    pm.add_pod(make_pod("pod-old", "legacy", 1, 1024 * 1024 * 1024));
    // Frame only has pod-1. pod-old is gone.
    let desired = vec![make_spec("pod-1", "db", 2, 4096)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    assert!(result.to_evict.contains(&"pod-old".to_string()));
    assert!(result.to_boot.is_empty());
    assert!(result.to_replace.is_empty());
}
#[test]
fn reconciler_boots_pod_in_frame_but_not_running() {
    let pm = PodManager::new(); // Nothing running.
    let desired = vec![make_spec("pod-new", "web", 2, 4096)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    assert_eq!(result.to_boot.len(), 1);
    assert!(result.to_evict.is_empty());
    assert!(result.to_replace.is_empty());
}
#[test]
fn replacement_gated_by_frame_consistency_guard() {
    let mut pm = PodManager::new();
    pm.add_pod(make_pod("pod-1", "db", 2, 4096 * 1024 * 1024));
    let desired = vec![make_spec("pod-1", "db", 4, 8192)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    assert_eq!(result.to_replace.len(), 1);
    // Guard: pod-1 IS in the frame → deny disruption.
    let guard = FrameConsistencyGuard::from_assignments(&desired);
    let (old_pod_id, _) = &result.to_replace[0];
    assert!(!guard.allow_disruption(old_pod_id, &DisruptionTarget::VerticalResize));
}
#[test]
fn replacement_allowed_when_frame_converged() {
    let mut pm = PodManager::new();
    pm.add_pod(make_pod("pod-1", "db", 2, 4096 * 1024 * 1024));
    // Frame has pod-2 (new, replacement). pod-1 is gone.
    let desired = vec![make_spec("pod-2", "db", 4, 8192)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    // pod-1 is running but not in frame → evict.
    assert!(result.to_evict.contains(&"pod-1".to_string()));
    // pod-2 is in frame but not running → boot.
    assert_eq!(result.to_boot.len(), 1);
    // Guard: pod-1 NOT in frame → allow eviction.
    let guard = FrameConsistencyGuard::from_assignments(&desired);
    assert!(guard.allow_disruption("pod-1", &DisruptionTarget::ScaleDown));
}
#[test]
fn pod_id_keying_not_workload_id() {
    // Regression test: reconciler must key on pod_id, not workload_id.
    let mut pm = PodManager::new();
    pm.add_pod(make_pod("pod-a", "db", 2, 4096 * 1024 * 1024));
    pm.add_pod(make_pod("pod-b", "db", 2, 4096 * 1024 * 1024));
    // Frame only has pod-a. pod-b should be evicted.
    let desired = vec![make_spec("pod-a", "db", 2, 4096)];
    let result = Reconciler::reconcile(&desired, &pm, "test.internal");
    assert!(result.to_evict.contains(&"pod-b".to_string()));
    assert!(!result.to_evict.contains(&"pod-a".to_string()));
    assert!(result.to_boot.is_empty());
}
