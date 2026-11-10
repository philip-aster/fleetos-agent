// SPDX-License-Identifier: Apache-2.0
//! Phase 8.8: WorkloadStatusReport builder tests (Ruling D / CR-CORE-3).
//!
//! Verifies build_status_report maps all Pod fields correctly, including
//! the Ruling D readiness gate fields (started, policy_enforced,
//! router_connected) and CR-CORE-3 fields (restart_count).
//!
//! Pure computation tests — no gRPC, no storage, no eBPF.
use fleetos_agent::workloads::RuntimeKind;
use fleetos_agent::workloads::pod_manager::{Pod, PodState};
use fleetos_agent::workloads::status::build_status_report;
use fleetos_core::hash::IdentityFingerprint;

fn make_pod(pod_id: &str) -> Pod {
    Pod::new(
        pod_id.to_string(),
        "test-workload".to_string(),
        "test-tenant".to_string(),
        "primary".to_string(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([0u8; 16]),
    )
}

// --- Identity fields ---

#[test]
fn maps_identity_fields() {
    let pod = make_pod("pod-abc-123");
    let report = build_status_report(&pod);
    assert_eq!(report.pod_id, "pod-abc-123");
    assert_eq!(report.workload_id, "test-workload");
    assert_eq!(report.tenant_id, "test-tenant");
}

// --- Probe fields ---

#[test]
fn maps_probe_fields() {
    let mut pod = make_pod("pod-1");
    pod.probe_live = true;
    pod.probe_ready = false;
    let report = build_status_report(&pod);
    assert!(report.live);
    assert!(!report.ready);
}

// --- CR-CORE-3 fields ---

#[test]
fn maps_restart_count() {
    let mut pod = make_pod("pod-1");
    pod.restart_count = 5;
    assert_eq!(build_status_report(&pod).restart_count, 5);
}

#[test]
fn maps_started() {
    let mut pod = make_pod("pod-1");
    pod.started = true;
    assert!(build_status_report(&pod).started);
    pod.started = false;
    assert!(!build_status_report(&pod).started);
}

// --- Ruling D readiness gate fields ---

#[test]
fn maps_policy_enforced() {
    let mut pod = make_pod("pod-1");
    pod.policy_enforced = true;
    assert!(build_status_report(&pod).policy_enforced);
    pod.policy_enforced = false;
    assert!(!build_status_report(&pod).policy_enforced);
}

#[test]
fn maps_router_connected() {
    let mut pod = make_pod("pod-1");
    pod.router_connected = true;
    assert!(build_status_report(&pod).router_connected);
    pod.router_connected = false;
    assert!(!build_status_report(&pod).router_connected);
}

// --- Full gate evaluation ---

#[test]
fn all_gates_satisfied_reports_fully_ready() {
    let mut pod = make_pod("pod-1");
    pod.state = PodState::Running;
    pod.started = true;
    pod.policy_enforced = true;
    pod.router_connected = true;
    pod.probe_live = true;
    pod.probe_ready = true;
    let report = build_status_report(&pod);
    assert!(report.live);
    assert!(report.ready);
    assert!(report.started);
    assert!(report.policy_enforced);
    assert!(report.router_connected);
}

#[test]
fn policy_not_enforced_visible_in_report() {
    let mut pod = make_pod("pod-1");
    pod.started = true;
    pod.policy_enforced = false;
    pod.router_connected = true;
    let report = build_status_report(&pod);
    assert!(report.started);
    assert!(!report.policy_enforced);
    assert!(report.router_connected);
}

// --- Timestamp ---

#[test]
fn observed_at_unix_is_recent() {
    let pod = make_pod("pod-1");
    let report = build_status_report(&pod);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(report.observed_at_unix > 0);
    assert!(now - report.observed_at_unix < 60);
}

// --- Fresh pod defaults ---

#[test]
fn freshly_created_pod_reports_all_false() {
    let pod = make_pod("pod-fresh");
    let report = build_status_report(&pod);
    assert!(!report.live);
    assert!(!report.ready);
    assert!(!report.started);
    assert!(!report.policy_enforced);
    assert!(!report.router_connected);
    assert_eq!(report.restart_count, 0);
}
