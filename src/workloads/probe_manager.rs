// SPDX-License-Identifier: Apache-2.0
//! ProbeManager: owns per-pod ProbeSetRunner instances and drives probe ticks.
//!
//! Created when a pod boots, removed when evicted. The probe loop calls
//! `tick()` periodically; the manager runs probes for each tracked pod and
//! returns the results so the caller can update Pod state.

use crate::workloads::probes::ProbeSetRunner;
use std::collections::HashMap;

/// Result of a single probe tick for one pod.
#[derive(Debug, Clone)]
pub struct ProbeTickResult {
    pub pod_id: String,
    /// Liveness probe is passing (threshold-aware).
    pub live: bool,
    /// Readiness probe is passing (threshold-aware).
    pub ready: bool,
    /// All configured probes are currently passing (startup complete, and
    /// liveness + readiness passing where configured). This is a *level*, not
    /// an edge: true on every tick where probes pass. The probe loop combines
    /// it with the pod's current state to decide the Booting → Running transition.
    pub all_probes_passing: bool,
    /// True if a probe failed this tick (for event emission).
    pub probe_failed: bool,
}

/// Manages per-pod ProbeSetRunner instances.
///
/// Thread-safe: held behind Arc<RwLock<>> so the probe loop can tick
/// while WorkloadManager boots/evicts pods concurrently.
pub struct ProbeManager {
    /// pod_id -> ProbeSetRunner
    runners: HashMap<String, ProbeSetRunner>,
}

impl ProbeManager {
    pub fn new() -> Self {
        Self {
            runners: HashMap::new(),
        }
    }

    /// Register a probe runner for a pod. Called when the pod boots.
    ///
    /// If the pod has no probes configured, registers a runner that always
    /// reports (live=true, ready=true) so the pod transitions to Running
    /// immediately after boot.
    pub fn register_pod(&mut self, pod_id: &str, runner: ProbeSetRunner) {
        self.runners.insert(pod_id.to_string(), runner);
    }

    /// Remove a pod's probe runner. Called when the pod is evicted/stopped.
    pub fn unregister_pod(&mut self, pod_id: &str) {
        self.runners.remove(pod_id);
    }

    /// Run probes for all tracked pods and return results.
    ///
    /// This is called by the probe loop task. For each pod:
    /// 1. Run the ProbeSetRunner.
    /// 2. Determine if the pod should transition to Running.
    /// 3. Determine if the pod should be restarted (liveness failure + restart policy).
    ///
    /// Returns results so the caller can update Pod state and emit events.
    pub fn tick(&mut self) -> Vec<ProbeTickResult> {
        let mut results = Vec::new();
        let pod_ids: Vec<String> = self.runners.keys().cloned().collect();

        for pod_id in pod_ids {
            if let Some(runner) = self.runners.get_mut(&pod_id) {
                let (live, ready) = runner.run_probes();
                let all_passing = runner.all_passing();
                let probe_failed = !live || !ready;

                results.push(ProbeTickResult {
                    pod_id,
                    live,
                    ready,
                    all_probes_passing: all_passing,
                    probe_failed,
                });
            }
        }

        results
    }

    /// Check if a pod's probes are all passing (for startup gating).
    pub fn is_pod_ready(&self, pod_id: &str) -> bool {
        self.runners
            .get(pod_id)
            .map(|r| r.all_passing())
            .unwrap_or(true) // No probes = ready
    }
}

impl Default for ProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workloads::probes::ProbeSetRunner;
    use fleetos_core::proto::workload::{ExecCheck, Probe, ProbeSet};

    fn make_exec_probe(pass: bool) -> Probe {
        // For testing, we use a command that will succeed or fail
        let cmd = if pass {
            vec!["true".to_string()]
        } else {
            vec!["false".to_string()]
        };
        Probe {
            check: Some(fleetos_core::proto::fleetos::probe::Check::Exec(
                ExecCheck { command: cmd },
            )),
            initial_delay_seconds: 0,
            period_seconds: 1,
            timeout_seconds: 1,
            success_threshold: 1,
            failure_threshold: 1,
        }
    }

    #[test]
    fn probe_manager_register_and_tick() {
        let mut mgr = ProbeManager::new();

        // Create a runner with a passing liveness probe
        let liveness = make_exec_probe(true);
        let readiness = make_exec_probe(true);
        let probe_set = ProbeSet {
            liveness: Some(liveness),
            readiness: Some(readiness),
            startup: None,
        };
        let runner = ProbeSetRunner::new(Some(&probe_set));
        mgr.register_pod("pod-1", runner);

        let results = mgr.tick();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pod_id, "pod-1");
        assert!(results[0].live);
        assert!(results[0].ready);
    }

    #[test]
    fn probe_manager_unregister() {
        let mut mgr = ProbeManager::new();
        let probe_set = ProbeSet {
            liveness: None,
            readiness: None,
            startup: None,
        };
        let runner = ProbeSetRunner::new(Some(&probe_set));
        mgr.register_pod("pod-1", runner);
        mgr.unregister_pod("pod-1");

        let results = mgr.tick();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn no_probes_means_ready() {
        let mgr = ProbeManager::new();
        // No runner registered = no probes = ready
        assert!(mgr.is_pod_ready("nonexistent"));
    }
}
