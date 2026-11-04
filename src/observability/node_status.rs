// SPDX-License-Identifier: Apache-2.0
//! Node liveness heartbeat reporter (Phase 8.4.3 / CORE-WI-6).
//!
//! Emits `NodeStatusReport` heartbeats on a fixed cadence so control's
//! `node_controller` can refresh `NodeRecord.last_heartbeat` and avoid
//! evicting healthy nodes (Ruling I).
//!
//! Design decisions from the CORE-WI-6 handover:
//! - `node_svid` is the node's SPIFFE ID string (the `NodeRecord` key).
//! - `observed_at_unix` is informational/diagnostic only — control does
//!   lease math on its own receipt clock (anti-postdating rule).
//! - Cadence is comfortably inside control's `node_lease_timeout_secs`
//!   (default 3600s). Recommended 30–60s with a config key.
//! - No eBPF interaction, no storage keyspace, no sealing. Pure unary client.
//!
//! The heartbeat is a purely additive liveness signal. If the RPC fails
//! transiently, we log and retry on the next tick — the lease timeout has
//! enormous margin over the heartbeat interval.
use crate::client::ControlPlaneClient;
use crate::client::unary;
use crate::error::AgentError;
use fleetos_core::proto::fleetos::NodeStatusReport;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
/// The NodeStatusReporter task.
///
/// Emits node heartbeats on a fixed cadence. The `node_svid` is the
/// string form of the node's SPIFFE ID, matching the `NodeRecord` key
/// in control's registry.
pub struct NodeStatusReporter {
    control_client: Arc<ControlPlaneClient>,
    /// The node's SPIFFE ID string
    /// (e.g., "spiffe://fleet.example.internal/ns/system/node/agent-1").
    node_svid: String,
    /// Heartbeat interval in seconds (from `[node] heartbeat_interval_secs`).
    interval_secs: u64,
}
impl NodeStatusReporter {
    pub fn new(
        control_client: Arc<ControlPlaneClient>,
        node_svid: String,
        interval_secs: u64,
    ) -> Self {
        Self {
            control_client,
            node_svid,
            interval_secs,
        }
    }
    /// Run the heartbeat loop until the shutdown signal fires.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.interval_secs);
        tracing::info!(
            interval_secs = self.interval_secs,
            node_svid = %self.node_svid,
            "node status reporter started"
        );
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("node status reporter shutting down");
                        return;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.send_heartbeat().await {
                        // Heartbeat failure is non-fatal. The lease timeout
                        // (default 3600s) has enormous margin over the
                        // heartbeat interval (default 30s). Log and retry
                        // on the next tick.
                        tracing::warn!(
                            error = %e,
                            "node heartbeat failed; will retry next tick"
                        );
                    }
                }
            }
        }
    }
    /// Build and send a single heartbeat.
    async fn send_heartbeat(&self) -> Result<(), AgentError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let report = NodeStatusReport {
            node_svid: self.node_svid.clone(),
            // Diagnostic only — control ignores this for lease math
            // (anti-postdating rule from CORE-WI-6).
            observed_at_unix: now_unix,
        };
        unary::report_node_status(&self.control_client, report).await?;
        tracing::debug!("node heartbeat sent");
        Ok(())
    }
}
