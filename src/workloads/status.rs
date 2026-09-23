// SPDX-License-Identifier: Apache-2.0
//! WorkloadStatusReport builder and reporter.
//!
//! Reports workload liveness/readiness to control.
//! Ruling D: a pod is not `Running` until (started) AND (policy_enforced)
//! AND (router_connected). The `policy_enforced` field is TODO(Ruling D)
//! until the state.proto change lands; builder structured so it's a
//! one-line wire later.
//!
//! CR-CORE-3: `restart_count` and `started` fields for K8s parity.
//! Directive A.1: `router_connected` for node-level routing health.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fleetos_core::proto::fleetos::workload_status_service_client::WorkloadStatusServiceClient;
use fleetos_core::proto::state::WorkloadStatusReport;
use tokio::sync::watch;
use tonic::transport::Channel;

use super::pod_manager::{Pod, PodManager};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build a WorkloadStatusReport from a pod's current state.
///
/// `ready` = readiness probe passing (probe_ready).
/// `live` = liveness probe passing (probe_live).
/// `started` = startup probe completed.
/// `policy_enforced` = Ruling D gate (eBPF policy live for this pod).
/// `router_connected` = Directive A.1 (node-level routing health).
pub fn build_status_report(pod: &Pod) -> WorkloadStatusReport {
    WorkloadStatusReport {
        pod_id: pod.pod_id.clone(),
        workload_id: pod.workload_id.clone(),
        tenant_id: pod.tenant_id.clone(),
        ready: pod.probe_ready,
        live: pod.probe_live,
        observed_at_unix: now_unix(),
        restart_count: pod.restart_count,
        started: pod.started,
        policy_enforced: pod.policy_enforced,
        router_connected: pod.router_connected,
    }
}

/// Periodic status reporter. Iterates all pods, builds status reports,
/// and sends them via WorkloadStatusService.ReportWorkloadStatus.
pub struct StatusReporter {
    pod_manager: Arc<tokio::sync::RwLock<PodManager>>,
    client: WorkloadStatusServiceClient<Channel>,
    interval: Duration,
}

impl StatusReporter {
    pub fn new(
        pod_manager: Arc<tokio::sync::RwLock<PodManager>>,
        client: WorkloadStatusServiceClient<Channel>,
        interval: Duration,
    ) -> Self {
        Self {
            pod_manager,
            client,
            interval,
        }
    }

    /// Run the reporter loop. Periodically sends status reports for all pods.
    /// Runs until the shutdown signal fires.
    pub async fn run_reporter_loop(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), crate::error::AgentError> {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("status reporter shutting down");
                        return Ok(());
                    }
                }
                _ = interval.tick() => {
                    self.report_all_pods().await?;
                }
            }
        }
    }

    /// Send status reports for all pods.
    async fn report_all_pods(&mut self) -> Result<(), crate::error::AgentError> {
        let reports: Vec<WorkloadStatusReport> = {
            let manager = self.pod_manager.read().await;
            manager
                .all_pods()
                .map(|pod| build_status_report(pod))
                .collect()
        };

        for report in reports {
            match self.client.report_workload_status(report).await {
                Ok(_ack) => {
                    tracing::debug!("status report sent");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to send status report");
                }
            }
        }

        Ok(())
    }
}
