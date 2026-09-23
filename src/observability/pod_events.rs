// SPDX-License-Identifier: Apache-2.0
//! Pod lifecycle event reporter.
//!
//! CR-CORE-8 / CR-CTRL-7: Reports pod lifecycle events to control.
//! Batches events and sends via PodEventService.ReportPodEvents.
//!
//! Canonical event vocabulary: Pulled, Created, Started, ProbeFailed,
//! BackOff, OOMKilled, Evicting, GracePeriodExpired, FailedScheduling,
//! Resizing, Resized.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fleetos_core::proto::fleetos::{
    PodEvent, ReportPodEventsRequest, pod_event_service_client::PodEventServiceClient,
};
use tokio::sync::watch;
use tonic::transport::Channel;

use crate::error::AgentError;

/// Canonical pod event types (CR-CTRL-7 vocabulary).
pub mod event_types {
    pub const PULLED: &str = "Pulled";
    pub const CREATED: &str = "Created";
    pub const STARTED: &str = "Started";
    pub const PROBE_FAILED: &str = "ProbeFailed";
    pub const BACK_OFF: &str = "BackOff";
    pub const OOM_KILLED: &str = "OOMKilled";
    pub const EVICTING: &str = "Evicting";
    pub const GRACE_PERIOD_EXPIRED: &str = "GracePeriodExpired";
    pub const FAILED_SCHEDULING: &str = "FailedScheduling";
    pub const RESIZING: &str = "Resizing";
    pub const RESIZED: &str = "Resized";
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Pod lifecycle event reporter. Batches events and sends them
/// via PodEventService.ReportPodEvents.
pub struct PodEventReporter {
    node_id: String,
    client: PodEventServiceClient<Channel>,
    batch: Vec<PodEvent>,
    batch_size: usize,
    flush_interval: Duration,
}

impl PodEventReporter {
    pub fn new(
        node_id: String,
        client: PodEventServiceClient<Channel>,
        batch_size: usize,
        flush_interval: Duration,
    ) -> Self {
        Self {
            node_id,
            client,
            batch: Vec::with_capacity(batch_size),
            batch_size,
            flush_interval,
        }
    }

    /// Record a pod event. Adds to the batch; flushes when batch is full.
    pub async fn record_event(
        &mut self,
        pod_id: &str,
        event_type: &str,
        reason: &str,
        message: &str,
    ) -> Result<(), AgentError> {
        let event = PodEvent {
            pod_id: pod_id.to_string(),
            node_id: self.node_id.clone(),
            event_type: event_type.to_string(),
            reason: reason.to_string(),
            message: message.to_string(),
            timestamp_unix: now_unix(),
            count: 1,
        };

        self.batch.push(event);

        if self.batch.len() >= self.batch_size {
            self.flush().await?;
        }

        Ok(())
    }

    /// Flush the current batch of events.
    pub async fn flush(&mut self) -> Result<(), AgentError> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let events = std::mem::take(&mut self.batch);
        let request = ReportPodEventsRequest { events };

        match self.client.report_pod_events(request).await {
            Ok(_response) => {
                tracing::debug!("pod events flushed");
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to flush pod events");
                return Err(AgentError::Internal(format!(
                    "failed to flush pod events: {}",
                    e
                )));
            }
        }

        Ok(())
    }

    /// Run the periodic flush loop. Flushes the batch at regular intervals
    /// even if the batch isn't full. Runs until the shutdown signal fires.
    pub async fn run_flush_loop(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), AgentError> {
        let mut interval = tokio::time::interval(self.flush_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        // Flush remaining events before shutdown.
                        let _ = self.flush().await;
                        tracing::info!("pod event reporter shutting down");
                        return Ok(());
                    }
                }
                _ = interval.tick() => {
                    if let Err(e) = self.flush().await {
                        tracing::warn!(error = %e, "failed to flush pod events");
                    }
                }
            }
        }
    }
}
