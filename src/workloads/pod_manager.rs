// SPDX-License-Identifier: Apache-2.0
//! Pod state machine and lifecycle management.
//!
//! Tracks running pods and their states. The pod state machine is:
//! Pending → Booting → Running → Terminating → Stopped
//!
//! Ruling D: a pod is not `Running` until (started) AND (policy_enforced)
//! AND (router_connected). The status reporter enforces this gate.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use fleetos_core::hash::IdentityFingerprint;

use super::RuntimeKind;

/// Pod lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodState {
    /// Assigned but not yet booting.
    Pending,
    /// Boot in progress (boot-race guard applies for MicroVMs).
    Booting,
    /// Running and ready (all readiness gates passed).
    Running,
    /// Terminating with grace period.
    Terminating,
    /// Stopped and awaiting cleanup.
    Stopped,
}

/// A running pod on this node.
#[derive(Debug, Clone)]
pub struct Pod {
    /// Unique pod ID.
    pub pod_id: String,
    /// Workload ID this pod belongs to.
    pub workload_id: String,
    /// Tenant ID.
    pub tenant_id: String,
    /// Role (primary, replica, etc.).
    pub role: String,
    /// Runtime kind.
    pub runtime: RuntimeKind,
    /// Current state.
    pub state: PodState,
    /// Whether the workload process has started.
    pub started: bool,
    /// Whether eBPF policy is enforced for this pod (Ruling D gate).
    pub policy_enforced: bool,
    /// Whether router connectivity is confirmed (Ruling D gate).
    pub router_connected: bool,
    /// Restart count.
    pub restart_count: u32,
    /// When the pod was created.
    pub created_at_unix: u64,
    /// When the pod last reported status.
    pub last_status_at_unix: u64,
    /// Container/MicroVM PID or handle.
    pub pid: Option<u32>,
    /// VSOCK CID for MicroVMs.
    pub vsock_cid: Option<u32>,
    /// Identity fingerprint for this pod's workload.
    pub fingerprint: IdentityFingerprint,
    /// Readiness probe passing (separate from Ruling D gate).
    pub probe_ready: bool,
    /// Liveness probe passing.
    pub probe_live: bool,
    /// Whether a `ProbeFailed` event has already been emitted for the current
    /// failure episode. Edge-trigger guard: set when we emit, cleared when
    /// probes recover, so we don't spam on every red tick.
    pub probe_failure_reported: bool,
    /// Whether the pod has ever been observed all-passing. Gates `ProbeFailed`
    /// emission so transient failures during initial startup (before the pod
    /// has ever been healthy) don't emit noise.
    pub probe_ever_passed: bool,
}

impl Pod {
    /// Create a new pod in Pending state.
    pub fn new(
        pod_id: String,
        workload_id: String,
        tenant_id: String,
        role: String,
        runtime: RuntimeKind,
        fingerprint: IdentityFingerprint,
    ) -> Self {
        Self {
            pod_id,
            workload_id,
            tenant_id,
            role,
            runtime,
            state: PodState::Pending,
            started: false,
            policy_enforced: false,
            router_connected: false,
            restart_count: 0,
            created_at_unix: now_unix(),
            last_status_at_unix: 0,
            pid: None,
            vsock_cid: None,
            fingerprint,
            probe_ready: false,
            probe_live: false,
            probe_failure_reported: false,
            probe_ever_passed: false,
        }
    }

    /// Whether the pod is fully ready (all readiness gates passed).
    /// Ruling D: started AND policy_enforced AND router_connected.
    pub fn is_ready(&self) -> bool {
        self.state == PodState::Running
            && self.started
            && self.policy_enforced
            && self.router_connected
    }

    /// Whether the pod is alive (process running).
    pub fn is_live(&self) -> bool {
        matches!(self.state, PodState::Running | PodState::Booting)
    }

    /// Transition to a new state.
    pub fn transition_to(&mut self, new_state: PodState) {
        self.state = new_state;
    }

    /// Mark the workload process as started.
    pub fn mark_started(&mut self) {
        self.started = true;
    }

    /// Mark policy as enforced (Ruling D gate).
    pub fn mark_policy_enforced(&mut self) {
        self.policy_enforced = true;
    }

    /// Mark router connectivity confirmed (Ruling D gate).
    pub fn mark_router_connected(&mut self) {
        self.router_connected = true;
    }

    /// Increment restart count.
    pub fn increment_restart(&mut self) {
        self.restart_count += 1;
    }

    /// Update last status timestamp.
    pub fn touch_status(&mut self) {
        self.last_status_at_unix = now_unix();
    }

    /// Get the restart policy for this pod.
    /// Returns Never if not configured.
    pub fn restart_policy(&self) -> fleetos_core::proto::workload::RestartPolicy {
        // In a full implementation, this would read from the PodSpec.
        // For now, default to Always (K8s default).
        fleetos_core::proto::workload::RestartPolicy::Always
    }

    /// Check if the pod can transition to Running based on Ruling D gate.
    /// Gate: started AND policy_enforced AND router_connected.
    pub fn can_transition_to_running(&self) -> bool {
        self.started && self.policy_enforced && self.router_connected
    }

    /// Transition from Booting to Running if the gate is satisfied.
    /// Returns true if the transition occurred.
    pub fn try_transition_to_running(&mut self) -> bool {
        if self.state == PodState::Booting && self.can_transition_to_running() {
            self.transition_to(PodState::Running);
            true
        } else {
            false
        }
    }

    /// Transition to Terminating state.
    pub fn start_terminating(&mut self) {
        if self.state == PodState::Running {
            self.transition_to(PodState::Terminating);
        }
    }

    /// Transition from Terminating to Stopped.
    pub fn finish_terminating(&mut self) {
        if self.state == PodState::Terminating {
            self.transition_to(PodState::Stopped);
        }
    }

    /// Transition to Terminating for eviction, from any active state.
    pub fn begin_eviction(&mut self) {
        if matches!(
            self.state,
            PodState::Pending | PodState::Booting | PodState::Running
        ) {
            self.state = PodState::Terminating;
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Manages all pods on this node.
pub struct PodManager {
    pods: HashMap<String, Pod>,
}

impl PodManager {
    pub fn new() -> Self {
        Self {
            pods: HashMap::new(),
        }
    }

    /// Add a pod.
    pub fn add_pod(&mut self, pod: Pod) {
        self.pods.insert(pod.pod_id.clone(), pod);
    }

    /// Get a pod by ID.
    pub fn get_pod(&self, pod_id: &str) -> Option<&Pod> {
        self.pods.get(pod_id)
    }

    /// Get a mutable pod by ID.
    pub fn get_pod_mut(&mut self, pod_id: &str) -> Option<&mut Pod> {
        self.pods.get_mut(pod_id)
    }

    /// Remove a pod.
    pub fn remove_pod(&mut self, pod_id: &str) -> Option<Pod> {
        self.pods.remove(pod_id)
    }

    /// Get all pods.
    pub fn all_pods(&self) -> impl Iterator<Item = &Pod> {
        self.pods.values()
    }

    /// Get all pods for a workload.
    pub fn pods_for_workload(&self, workload_id: &str) -> Vec<&Pod> {
        self.pods
            .values()
            .filter(|p| p.workload_id == workload_id)
            .collect()
    }

    /// Get all running pods.
    pub fn running_pods(&self) -> Vec<&Pod> {
        self.pods
            .values()
            .filter(|p| p.state == PodState::Running)
            .collect()
    }

    /// Get all pod IDs.
    pub fn pod_ids(&self) -> Vec<String> {
        self.pods.keys().cloned().collect()
    }

    /// Count of pods.
    pub fn len(&self) -> usize {
        self.pods.len()
    }

    /// Whether empty.
    pub fn is_empty(&self) -> bool {
        self.pods.is_empty()
    }

    /// Get all pods mutably (Phase 7.4 readiness-gate re-evaluation).
    pub fn all_pods_mut(&mut self) -> impl Iterator<Item = &mut Pod> {
        self.pods.values_mut()
    }
}
