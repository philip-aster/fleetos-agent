// SPDX-License-Identifier: Apache-2.0
//! Full-state reconciler: desired assignments vs running pods.
//!
//! Ruling B: every `ScheduleUpdate` frame is full state. The reconciler
//! computes the diff and produces boot/evict decisions:
//! - Present in frame, absent locally → boot
//! - Absent in frame, present locally → graceful eviction (grace period)
//!
//! Full-state reconcile IS the eviction mechanism. No separate Evict RPC needed.

use std::collections::HashSet;

use super::WorkloadSpec;
use super::pod_manager::{PodManager, PodState};

/// Reconciliation result.
#[derive(Debug, Default)]
pub struct ReconcileResult {
    /// Pods to boot.
    pub to_boot: Vec<WorkloadSpec>,
    /// Pod IDs to evict.
    pub to_evict: Vec<String>,
}

impl ReconcileResult {
    pub fn is_empty(&self) -> bool {
        self.to_boot.is_empty() && self.to_evict.is_empty()
    }
}

/// Full-state reconciler.
pub struct Reconciler;

impl Reconciler {
    /// Reconcile desired assignments against running pods.
    ///
    /// This is a pure function: it computes the diff without side effects.
    /// The caller applies the decisions.
    pub fn reconcile(
        desired: &[WorkloadSpec],
        running: &PodManager,
        _trust_domain: &str,
    ) -> ReconcileResult {
        let mut result = ReconcileResult::default();

        // Build set of desired pod IDs.
        let desired_ids: HashSet<&str> = desired.iter().map(|w| w.workload_id.as_str()).collect();

        // Find pods to boot: in desired, not running.
        let running_ids: HashSet<&str> = running
            .all_pods()
            .filter(|p| !matches!(p.state, PodState::Terminating | PodState::Stopped))
            .map(|p| p.workload_id.as_str())
            .collect();

        for spec in desired {
            if !running_ids.contains(spec.workload_id.as_str()) {
                result.to_boot.push(spec.clone());
            }
        }

        // Find pods to evict: running, not in desired.
        for pod in running.all_pods() {
            if !matches!(pod.state, PodState::Terminating | PodState::Stopped)
                && !desired_ids.contains(pod.workload_id.as_str())
            {
                result.to_evict.push(pod.pod_id.clone());
            }
        }

        result
    }
}
