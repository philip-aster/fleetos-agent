// SPDX-License-Identifier: Apache-2.0
//! Full-state reconciler: desired assignments vs running pods.
//!
//! Ruling B: every `ScheduleUpdate` frame is full state. The reconciler
//! computes the diff and produces boot/evict/replace decisions.
//!
//! Phase 8.6.1: Keys on `pod_id` (not `workload_id`), detects footprint
//! mismatches (vcpus/memory), and produces replacement actions.
use super::WorkloadSpec;
use super::pod_manager::{PodManager, PodState};
use std::collections::HashMap;
/// Reconciliation result.
#[derive(Debug, Default)]
pub struct ReconcileResult {
    /// Pods to boot (in frame, not running).
    pub to_boot: Vec<WorkloadSpec>,
    /// Pod IDs to evict (running, not in frame).
    pub to_evict: Vec<String>,
    /// Phase 8.6.1: Pods whose footprint doesn't match the frame.
    /// Each entry is (old_pod_id, new_assignment).
    pub to_replace: Vec<(String, WorkloadSpec)>,
}
impl ReconcileResult {
    pub fn is_empty(&self) -> bool {
        self.to_boot.is_empty() && self.to_evict.is_empty() && self.to_replace.is_empty()
    }
}
/// Full-state reconciler.
pub struct Reconciler;
impl Reconciler {
    /// Reconcile desired assignments against running pods.
    ///
    /// Phase 8.6.1: Keys on `pod_id` for correct identity tracking.
    /// Detects footprint mismatches (vcpus/memory) to trigger VPA-driven
    /// replacements.
    pub fn reconcile(
        desired: &[WorkloadSpec],
        running: &PodManager,
        _trust_domain: &str,
    ) -> ReconcileResult {
        let mut result = ReconcileResult::default();
        // Build a map of desired assignments by pod_id.
        let mut desired_by_pod_id: HashMap<String, &WorkloadSpec> = HashMap::new();
        for spec in desired {
            if let Some(pod_spec) = &spec.pod_spec {
                if let Some(pod_id) = &pod_spec.pod_id {
                    desired_by_pod_id.insert(pod_id.clone(), spec);
                }
            }
        }
        // Build a map of running pods by pod_id.
        let mut running_by_pod_id: HashMap<&str, &super::pod_manager::Pod> = HashMap::new();
        for pod in running.all_pods() {
            if !matches!(pod.state, PodState::Terminating | PodState::Stopped) {
                running_by_pod_id.insert(pod.pod_id.as_str(), pod);
            }
        }
        // Find pods to boot: in frame but not running.
        for (pod_id, spec) in &desired_by_pod_id {
            if !running_by_pod_id.contains_key(pod_id.as_str()) {
                result.to_boot.push((*spec).clone());
            }
        }
        // Find pods to evict: running but not in frame.
        for (pod_id, _pod) in &running_by_pod_id {
            if !desired_by_pod_id.contains_key(*pod_id) {
                result.to_evict.push(pod_id.to_string());
            }
        }
        // Phase 8.6.1: Detect footprint mismatches for pods that ARE in the frame.
        // If a running pod's vcpus/memory doesn't match the frame's desired
        // resources, it needs replacement (VPA RECREATE strategy).
        for (pod_id, pod) in &running_by_pod_id {
            if let Some(spec) = desired_by_pod_id.get(*pod_id) {
                if let Some(pod_spec) = &spec.pod_spec {
                    if let Some(resources) = &pod_spec.resources {
                        let desired_vcpus = resources.vcpus;
                        let desired_memory = (resources.memory_mb as u64) * 1024 * 1024;
                        if !pod.footprint_matches(desired_vcpus, desired_memory) {
                            result
                                .to_replace
                                .push((pod_id.to_string(), (*spec).clone()));
                        }
                    }
                }
            }
        }
        result
    }
}
