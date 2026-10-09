// SPDX-License-Identifier: Apache-2.0
//! Phase 8.1 tests: probe state machine, state transitions, event emission.

use fleetos_agent::workloads::RuntimeKind;
use fleetos_agent::workloads::pod_manager::{Pod, PodState};
use fleetos_agent::workloads::probe_manager::ProbeManager;
use fleetos_agent::workloads::probes::ProbeSetRunner;
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::workload::{ExecCheck, Probe, ProbeSet};

fn make_exec_probe(command: Vec<String>) -> Probe {
    Probe {
        check: Some(fleetos_core::proto::fleetos::probe::Check::Exec(
            ExecCheck { command },
        )),
        initial_delay_seconds: 0,
        period_seconds: 1,
        timeout_seconds: 1,
        success_threshold: 1,
        failure_threshold: 1,
    }
}

fn make_pod(pod_id: &str, state: PodState) -> Pod {
    let mut pod = Pod::new(
        pod_id.to_string(),
        "test-workload".to_string(),
        "test-tenant".to_string(),
        "primary".to_string(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([0u8; 16]),
    );
    pod.state = state;
    pod
}

#[test]
fn probe_manager_tick_returns_results() {
    let mut mgr = ProbeManager::new();
    let probe_set = ProbeSet {
        liveness: Some(make_exec_probe(vec!["true".to_string()])),
        readiness: Some(make_exec_probe(vec!["true".to_string()])),
        startup: None,
    };
    let runner = ProbeSetRunner::new(Some(&probe_set));
    mgr.register_pod("pod-1", runner);

    let results = mgr.tick();
    assert_eq!(results.len(), 1);
    assert!(results[0].live);
    assert!(results[0].ready);
}

#[test]
fn probe_manager_no_probes_means_ready() {
    let mgr = ProbeManager::new();
    assert!(mgr.is_pod_ready("nonexistent"));
}

#[test]
fn pod_state_transitions() {
    let mut pod = make_pod("pod-1", PodState::Booting);
    pod.started = true;
    pod.policy_enforced = true;
    pod.router_connected = true;

    assert!(pod.try_transition_to_running());
    assert_eq!(pod.state, PodState::Running);

    pod.start_terminating();
    assert_eq!(pod.state, PodState::Terminating);

    pod.finish_terminating();
    assert_eq!(pod.state, PodState::Stopped);
}

#[test]
fn pod_gate_blocks_transition() {
    let mut pod = make_pod("pod-1", PodState::Booting);
    pod.started = true;
    pod.policy_enforced = false; // Gate not satisfied
    pod.router_connected = true;

    assert!(!pod.try_transition_to_running());
    assert_eq!(pod.state, PodState::Booting);
}
