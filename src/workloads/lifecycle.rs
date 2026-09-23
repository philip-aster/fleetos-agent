// SPDX-License-Identifier: Apache-2.0
//! Pod lifecycle: termination, restart policy, graceful shutdown.
//!
//! Termination: SIGTERM → grace wait → force kill.
//! Restart policy: agent-local restarts keep pod_id; when policy exhausts,
//! report live=false so control's ReassignPodId replaces the pod.

use std::time::Duration;

use fleetos_core::proto::workload::RestartPolicy;

use super::pod_manager::PodState;

/// Lifecycle manager for a single pod.
pub struct PodLifecycle {
    /// Restart policy.
    pub restart_policy: RestartPolicy,
    /// Restart count.
    pub restart_count: u32,
    /// Max restarts before giving up.
    pub max_restarts: u32,
    /// Grace period for termination.
    pub grace_period_secs: u64,
}

impl PodLifecycle {
    pub fn new(restart_policy: RestartPolicy, grace_period_secs: u64) -> Self {
        Self {
            restart_policy,
            restart_count: 0,
            max_restarts: 3,
            grace_period_secs,
        }
    }

    /// Whether the pod can be restarted.
    pub fn can_restart(&self) -> bool {
        match self.restart_policy {
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => true, // caller checks if it was a failure
            RestartPolicy::Never => false,
        }
    }

    /// Increment restart count and return whether we can still restart.
    pub fn record_restart(&mut self) -> bool {
        self.restart_count += 1;
        self.restart_count <= self.max_restarts && self.can_restart()
    }

    /// Grace period as Duration.
    pub fn grace_period(&self) -> Duration {
        Duration::from_secs(self.grace_period_secs)
    }
}

/// Termination plan.
#[derive(Debug, Clone)]
pub struct TerminationPlan {
    /// Grace period before force kill.
    pub grace_period: Duration,
    /// Whether to force kill after grace period.
    pub force_after_grace: bool,
}

impl TerminationPlan {
    /// Create a termination plan from grace period.
    pub fn new(grace_period_secs: u64) -> Self {
        Self {
            grace_period: Duration::from_secs(grace_period_secs),
            force_after_grace: true,
        }
    }

    /// Default termination plan (30s grace).
    pub fn default() -> Self {
        Self::new(30)
    }
}

/// Compute the target pod state after a lifecycle event.
pub fn next_state(current: PodState, failed: bool, lifecycle: &mut PodLifecycle) -> PodState {
    match current {
        PodState::Running if failed => {
            if lifecycle.record_restart() {
                PodState::Booting
            } else {
                PodState::Stopped
            }
        }
        PodState::Terminating => PodState::Stopped,
        other => other,
    }
}
