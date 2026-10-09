// SPDX-License-Identifier: Apache-2.0
//! ProbeLoop: periodic task that runs probes, updates Pod state, and emits events.
//!
//! This is the core of Phase 8.1. It:
//! 1. Ticks the ProbeManager every `probe_interval_secs`.
//! 2. Updates Pod.probe_live/probe_ready based on probe results.
//! 3. Transitions pods from Booting → Running when probes pass.
//! 4. Enforces RestartPolicy on liveness failure.
//! 5. Emits Started/ProbeFailed/BackOff/Evicting events.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};

use crate::observability::pod_events::PodEventReporter;
use crate::workloads::PodState;
use crate::workloads::pod_manager::PodManager;
use crate::workloads::probe_manager::{ProbeManager, ProbeTickResult};

use fleetos_core::proto::workload::RestartPolicy;

/// Configuration for the probe loop.
#[derive(Debug, Clone)]
pub struct ProbeLoopConfig {
    /// How often to run probes (seconds).
    pub probe_interval_secs: u64,
    /// Maximum consecutive liveness failures before restart (if policy allows).
    pub max_restart_attempts: u32,
}

impl Default for ProbeLoopConfig {
    fn default() -> Self {
        Self {
            probe_interval_secs: 10,
            max_restart_attempts: 3,
        }
    }
}

/// The probe loop task. Runs periodically, updates pod state, emits events.
pub struct ProbeLoop {
    probe_manager: Arc<RwLock<ProbeManager>>,
    pod_manager: Arc<RwLock<PodManager>>,
    event_reporter: Option<Arc<PodEventReporter>>,
    config: ProbeLoopConfig,
}

impl ProbeLoop {
    pub fn new(
        probe_manager: Arc<RwLock<ProbeManager>>,
        pod_manager: Arc<RwLock<PodManager>>,
        event_reporter: Option<Arc<PodEventReporter>>,
        config: ProbeLoopConfig,
    ) -> Self {
        Self {
            probe_manager,
            pod_manager,
            event_reporter,
            config,
        }
    }

    /// Run the probe loop until shutdown signal.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let mut interval =
            tokio::time::interval(Duration::from_secs(self.config.probe_interval_secs));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        tracing::info!(
            interval_secs = self.config.probe_interval_secs,
            "probe loop started"
        );

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("probe loop shutting down");
                        return;
                    }
                }
                _ = interval.tick() => {
                    self.tick().await;
                }
            }
        }
    }

    /// Single probe tick: run probes, update state, emit events.
    async fn tick(&self) {
        let results = self.probe_manager.write().await.tick();

        for result in results {
            self.process_probe_result(result).await;
        }
    }

    /// Process a single probe result: update pod state, then emit events.
    async fn process_probe_result(&self, result: ProbeTickResult) {
        let pod_id = result.pod_id.clone();
        let mut emit_started = false;
        let mut emit_back_off = false;
        let mut emit_probe_failed = false;

        {
            let mut pm = self.pod_manager.write().await;
            let Some(pod) = pm.get_pod_mut(&pod_id) else {
                return;
            };

            let was_running = pod.state == PodState::Running;
            pod.probe_live = result.live;
            pod.probe_ready = result.ready;

            // Track whether the pod has ever been observed all-passing.
            // This gates ProbeFailed emission to suppress startup noise.
            if result.all_probes_passing {
                pod.probe_ever_passed = true;
            }

            // Startup-suppressed ProbeFailed: emit only if the pod has been
            // observed passing at least once. A pod that has never been
            // healthy failing during initial startup is not surfaced.
            if result.probe_failed && pod.probe_ever_passed && !pod.probe_failure_reported {
                pod.probe_failure_reported = true;
                emit_probe_failed = true;
            } else if !result.probe_failed {
                // Recovered; allow re-emission on a future failure episode.
                pod.probe_failure_reported = false;
            }

            // Transition Booting → Running when probes pass.
            if pod.state == PodState::Booting && result.all_probes_passing {
                pod.transition_to(PodState::Running);
                emit_started = true;
            }

            // Handle liveness failure: restart if policy allows, else mark dead.
            if was_running && !result.live {
                match pod.restart_policy() {
                    RestartPolicy::Always | RestartPolicy::OnFailure => {
                        if pod.restart_count >= self.config.max_restart_attempts {
                            pod.probe_live = false;
                            emit_back_off = true;
                        } else {
                            pod.increment_restart();
                            pod.transition_to(PodState::Booting);
                            // Fresh failure episode after restart.
                            pod.probe_failure_reported = false;
                        }
                    }
                    RestartPolicy::Never => {
                        pod.probe_live = false;
                    }
                }
            }
        } // pod_manager write lock released here, BEFORE any network await

        if emit_probe_failed {
            self.emit_probe_failed(&pod_id).await;
        }
        if emit_started {
            tracing::info!(pod_id = %pod_id, "pod transitioned to Running");
            self.emit_started(&pod_id).await;
        }
        if emit_back_off {
            self.emit_back_off(&pod_id).await;
        }
    }

    /// Emit a Started event.
    async fn emit_started(&self, pod_id: &str) {
        if let Some(ref reporter) = self.event_reporter {
            if let Err(e) = reporter.record_event(pod_id, "Started", "", "").await {
                tracing::warn!(pod_id = %pod_id, error = %e, "failed to emit Started event");
            }
        }
    }

    /// Emit a BackOff event.
    async fn emit_back_off(&self, pod_id: &str) {
        if let Some(ref reporter) = self.event_reporter {
            if let Err(e) = reporter.record_event(pod_id, "BackOff", "", "").await {
                tracing::warn!(pod_id = %pod_id, error = %e, "failed to emit BackOff event");
            }
        }
    }

    /// Emit a ProbeFailed event.
    async fn emit_probe_failed(&self, pod_id: &str) {
        if let Some(ref reporter) = self.event_reporter {
            if let Err(e) = reporter.record_event(pod_id, "ProbeFailed", "", "").await {
                tracing::warn!(pod_id = %pod_id, error = %e, "failed to emit ProbeFailed event");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workloads::RuntimeKind;
    use crate::workloads::pod_manager::{Pod, PodState};
    use fleetos_core::hash::IdentityFingerprint;

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

    #[tokio::test]
    async fn probe_loop_updates_pod_state() {
        let probe_mgr = Arc::new(RwLock::new(
            crate::workloads::probe_manager::ProbeManager::new(),
        ));
        let pod_mgr = Arc::new(RwLock::new(PodManager::new()));

        // Add a pod in Booting state
        {
            let mut pm = pod_mgr.write().await;
            pm.add_pod(make_pod("pod-1", PodState::Booting));
        }

        // Register a probe runner that will pass
        {
            let mut pm = probe_mgr.write().await;
            let probe_set = fleetos_core::proto::workload::ProbeSet {
                liveness: None,
                readiness: None,
                startup: None,
            };
            let runner = crate::workloads::probes::ProbeSetRunner::new(Some(&probe_set));
            pm.register_pod("pod-1", runner);
        }

        let loop_ = ProbeLoop::new(probe_mgr, pod_mgr.clone(), None, ProbeLoopConfig::default());

        // Manually tick (not via the loop's interval)
        loop_.tick().await;

        // Pod should now be Running
        let pm = pod_mgr.read().await;
        let pod = pm.get_pod("pod-1").unwrap();
        assert_eq!(pod.state, PodState::Running);
        assert!(pod.probe_live);
        assert!(pod.probe_ready);
    }

    #[tokio::test]
    async fn probe_failed_is_edge_triggered() {
        let probe_mgr = Arc::new(RwLock::new(
            crate::workloads::probe_manager::ProbeManager::new(),
        ));
        let pod_mgr = Arc::new(RwLock::new(PodManager::new()));
        {
            let mut pm = pod_mgr.write().await;
            pm.add_pod(make_pod("pod-1", PodState::Running));
        }
        // event_reporter = None: emission is a no-op, but the edge-trigger
        // guard (probe_failure_reported) is still tracked and observable.
        let loop_ = ProbeLoop::new(probe_mgr, pod_mgr.clone(), None, ProbeLoopConfig::default());

        // Tick 1: all passing -> guard stays false.
        loop_
            .process_probe_result(ProbeTickResult {
                pod_id: "pod-1".to_string(),
                live: true,
                ready: true,
                all_probes_passing: true,
                probe_failed: false,
            })
            .await;
        assert!(
            !pod_mgr
                .read()
                .await
                .get_pod("pod-1")
                .unwrap()
                .probe_failure_reported
        );

        // Tick 2: readiness fails -> guard flips true (emit edge).
        loop_
            .process_probe_result(ProbeTickResult {
                pod_id: "pod-1".to_string(),
                live: true,
                ready: false,
                all_probes_passing: false,
                probe_failed: true,
            })
            .await;
        assert!(
            pod_mgr
                .read()
                .await
                .get_pod("pod-1")
                .unwrap()
                .probe_failure_reported
        );

        // Tick 3: still failing -> guard stays true (no re-emit / no spam).
        loop_
            .process_probe_result(ProbeTickResult {
                pod_id: "pod-1".to_string(),
                live: true,
                ready: false,
                all_probes_passing: false,
                probe_failed: true,
            })
            .await;
        assert!(
            pod_mgr
                .read()
                .await
                .get_pod("pod-1")
                .unwrap()
                .probe_failure_reported
        );

        // Tick 4: recovers -> guard resets, next failure episode can re-emit.
        loop_
            .process_probe_result(ProbeTickResult {
                pod_id: "pod-1".to_string(),
                live: true,
                ready: true,
                all_probes_passing: true,
                probe_failed: false,
            })
            .await;
        assert!(
            !pod_mgr
                .read()
                .await
                .get_pod("pod-1")
                .unwrap()
                .probe_failure_reported
        );
    }

    #[tokio::test]
    async fn probe_failed_suppressed_before_first_pass() {
        let probe_mgr = Arc::new(RwLock::new(
            crate::workloads::probe_manager::ProbeManager::new(),
        ));
        let pod_mgr = Arc::new(RwLock::new(PodManager::new()));
        {
            let mut pm = pod_mgr.write().await;
            pm.add_pod(make_pod("pod-1", PodState::Booting));
        }
        let loop_ = ProbeLoop::new(probe_mgr, pod_mgr.clone(), None, ProbeLoopConfig::default());
        loop_
            .process_probe_result(ProbeTickResult {
                pod_id: "pod-1".to_string(),
                live: true,
                ready: false,
                all_probes_passing: false,
                probe_failed: true,
            })
            .await;
        // Never passed -> ProbeFailed suppressed (probe_failure_reported stays false).
        let pm = pod_mgr.read().await;
        let pod = pm.get_pod("pod-1").unwrap();
        assert!(!pod.probe_failure_reported);
        assert!(!pod.probe_ever_passed);
    }

    #[tokio::test]
    async fn probe_failed_emitted_after_first_pass() {
        let probe_mgr = Arc::new(RwLock::new(
            crate::workloads::probe_manager::ProbeManager::new(),
        ));
        let pod_mgr = Arc::new(RwLock::new(PodManager::new()));
        {
            let mut pm = pod_mgr.write().await;
            let mut pod = make_pod("pod-1", PodState::Booting);
            pod.probe_ever_passed = true; // has been healthy before
            pm.add_pod(pod);
        }
        let loop_ = ProbeLoop::new(probe_mgr, pod_mgr.clone(), None, ProbeLoopConfig::default());
        loop_
            .process_probe_result(ProbeTickResult {
                pod_id: "pod-1".to_string(),
                live: true,
                ready: false,
                all_probes_passing: false,
                probe_failed: true,
            })
            .await;
        let pm = pod_mgr.read().await;
        assert!(pm.get_pod("pod-1").unwrap().probe_failure_reported);
    }
}
