// SPDX-License-Identifier: Apache-2.0
//! Phase 8.6.4: Frame-consistency guard tests.
use fleetos_agent::workloads::WorkloadSpec;
use fleetos_agent::workloads::disruption::{
    DisruptionGuard, DisruptionTarget, FrameConsistencyGuard,
};
use fleetos_core::proto::workload::PodSpec;
fn make_spec(pod_id: &str, workload_id: &str) -> WorkloadSpec {
    WorkloadSpec {
        workload_id: workload_id.to_string(),
        runtime: fleetos_agent::workloads::RuntimeKind::CloudHypervisor,
        image: "test-image".to_string(),
        role: "primary".to_string(),
        pod_spec: Some(PodSpec {
            pod_id: Some(pod_id.to_string()),
            ..Default::default()
        }),
        hostname: format!("{}.test.internal", workload_id),
    }
}
#[test]
fn guard_allows_disruption_when_pod_not_in_frame() {
    let assignments = vec![make_spec("pod-1", "db"), make_spec("pod-2", "web")];
    let guard = FrameConsistencyGuard::from_assignments(&assignments);
    // pod-3 is NOT in the frame → allow disruption.
    assert!(guard.allow_disruption("pod-3", &DisruptionTarget::ScaleDown));
    assert!(guard.allow_disruption("pod-3", &DisruptionTarget::VerticalResize));
    assert!(guard.allow_disruption("pod-3", &DisruptionTarget::NodeEviction));
}
#[test]
fn guard_denies_disruption_when_pod_in_frame() {
    let assignments = vec![make_spec("pod-1", "db"), make_spec("pod-2", "web")];
    let guard = FrameConsistencyGuard::from_assignments(&assignments);
    // pod-1 IS in the frame → deny disruption.
    assert!(!guard.allow_disruption("pod-1", &DisruptionTarget::ScaleDown));
    assert!(!guard.allow_disruption("pod-1", &DisruptionTarget::VerticalResize));
    assert!(!guard.allow_disruption("pod-2", &DisruptionTarget::NodeEviction));
}
#[test]
fn guard_is_target_agnostic() {
    // The frame-consistency check is the same regardless of DisruptionTarget.
    // This is by design: the guard checks frame presence, not budget.
    let assignments = vec![make_spec("pod-1", "db")];
    let guard = FrameConsistencyGuard::from_assignments(&assignments);
    let targets = [
        DisruptionTarget::VerticalResize,
        DisruptionTarget::ScaleDown,
        DisruptionTarget::NodeEviction,
        DisruptionTarget::WorkloadDelete,
    ];
    for target in &targets {
        assert!(!guard.allow_disruption("pod-1", target));
        assert!(guard.allow_disruption("pod-99", target));
    }
}
#[test]
fn guard_with_empty_frame_allows_all() {
    // Empty frame → all pods are "not in frame" → allow all disruptions.
    let guard = FrameConsistencyGuard::from_assignments(&[]);
    assert!(guard.allow_disruption("any-pod", &DisruptionTarget::ScaleDown));
}
#[test]
fn pod_in_frame_helper() {
    let assignments = vec![make_spec("pod-1", "db")];
    let guard = FrameConsistencyGuard::from_assignments(&assignments);
    assert!(guard.pod_in_frame("pod-1"));
    assert!(!guard.pod_in_frame("pod-2"));
}
