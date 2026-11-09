// SPDX-License-Identifier: Apache-2.0
//! Local disruption guard (Phase 8.6.2).
//!
//! Ruling (Lead Engineer, fleetos-control):
//! The agent does NOT have the budget. `WorkloadAssignment` carries `PodSpec`
//! but no `DisruptionBudget`. The budget lives in control's `workloads`
//! keyspace and is never streamed to the agent.
//!
//! What the agent's local guard checks is FRAME CONSISTENCY, not budget:
//!   1. Before terminating a pod, check: is this pod still in the latest frame?
//!   2. If yes → do NOT terminate. The frame still expects it.
//!   3. If no → proceed. The frame has converged past this pod.
//!
//! Why control's guard is structurally sufficient for the budget:
//! Every disruptive mutation is proposed through the leader and serialized by
//! the Raft log. The `BudgetBackedDisruptionGuard` evaluates against committed
//! placement state at proposal time. If denied, the Raft entry never lands,
//! the frame never reflects the reduction, and the agent never sees it.
//! The budget gate is linearizable by construction.
//!
//! This trait mirrors the control-side `DisruptionGuard` shape for future
//! symmetry, but the implementation is: check the frame, don't check the budget.
use super::WorkloadSpec;
use std::collections::HashSet;
/// The type of disruption being requested.
///
/// Mirrors the control-side `DisruptionTarget` enum. The `VerticalResize`
/// variant is wired in so the seam is ready if the guard's semantics ever
/// need to be refined (e.g., different frame-consistency rules per target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisruptionTarget {
    /// VPA-driven vertical resize (RECREATE strategy).
    VerticalResize,
    /// HPA or operator-initiated scale-down.
    ScaleDown,
    /// Node eviction (lease expiry, drain).
    NodeEviction,
    /// Operator-initiated workload deletion.
    WorkloadDelete,
}
/// Trait for gating disruptive operations.
///
/// The agent-local implementation performs a frame-consistency check.
/// It does NOT evaluate budgets — that is control's job at the Raft
/// proposal layer.
pub trait DisruptionGuard {
    /// Returns `true` if the disruption is allowed for the given pod.
    ///
    /// Frame-consistency semantics:
    /// - Pod IS in the latest frame → `false` (do not disrupt; frame expects it)
    /// - Pod is NOT in the latest frame → `true` (frame converged past it)
    fn allow_disruption(&self, pod_id: &str, target: &DisruptionTarget) -> bool;
}
/// Frame-consistency guard.
///
/// Constructed fresh from the latest `ScheduleUpdate` frame on each reconcile
/// cycle. The guard's answer is deterministic: if the pod_id is present in
/// the frame's assignment list, disruption is denied. If absent, allowed.
///
/// This is defense-in-depth against the agent's reconciler racing ahead of
/// the frame on stale local state. It is NOT a budget check and must not
/// become one.
pub struct FrameConsistencyGuard {
    /// The set of pod_ids present in the latest ScheduleUpdate frame.
    frame_pod_ids: HashSet<String>,
}
impl FrameConsistencyGuard {
    /// Construct a guard from the current frame's desired assignments.
    ///
    /// Extracts `pod_id` from each `WorkloadSpec`'s embedded `PodSpec`.
    /// Assignments without a `pod_id` are skipped (they cannot be matched).
    pub fn from_assignments(assignments: &[WorkloadSpec]) -> Self {
        let frame_pod_ids = assignments
            .iter()
            .filter_map(|spec| spec.pod_spec.as_ref().and_then(|ps| ps.pod_id.clone()))
            .collect();
        Self { frame_pod_ids }
    }
    /// Check if a pod_id is still present in the frame.
    pub fn pod_in_frame(&self, pod_id: &str) -> bool {
        self.frame_pod_ids.contains(pod_id)
    }
}
impl DisruptionGuard for FrameConsistencyGuard {
    fn allow_disruption(&self, pod_id: &str, _target: &DisruptionTarget) -> bool {
        // Frame consistency: if the pod is still in the frame, do NOT disrupt.
        // The frame still expects it. Wait for the next frame (which will only
        // reflect a reduction after control's BudgetBackedDisruptionGuard
        // approved the Raft entry).
        //
        // If the pod is NOT in the frame, the frame has already converged
        // past this pod → allow disruption.
        !self.frame_pod_ids.contains(pod_id)
    }
}
