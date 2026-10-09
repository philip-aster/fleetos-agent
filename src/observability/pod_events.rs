// SPDX-License-Identifier: Apache-2.0
//! Pod lifecycle event reporter.
//!
//! CR-CORE-8 / CR-CTRL-7: Reports pod lifecycle events to control.
//! Batches events and sends via PodEventService.ReportPodEvents.
//!
//! Concurrency: the reporter is shared across the probe loop, workload
//! manager, and the flush task via `Arc`. The batch uses interior
//! mutability (`tokio::sync::Mutex`) so all methods take `&self`.
//! Locks are never held across a network `.await`.

use crate::error::AgentError;
use fleetos_core::proto::fleetos::{
    PodEvent, ReportPodEventsRequest, pod_event_service_client::PodEventServiceClient,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, watch};
use tonic::transport::Channel;

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

/// Pod lifecycle event reporter. Batches events and sends them via
/// PodEventService.ReportPodEvents.
///
/// All methods take `&self`; safe to share behind an `Arc`.
pub struct PodEventReporter {
    node_id: String,
    client: PodEventServiceClient<Channel>,
    /// Interior mutability so `record_event` / `flush` can take `&self`.
    batch: Mutex<Vec<PodEvent>>,
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
            batch: Mutex::new(Vec::with_capacity(batch_size)),
            batch_size,
            flush_interval,
        }
    }

    /// Record a pod event. Adds to the batch; flushes when the batch is full.
    pub async fn record_event(
        &self,
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
        // Decide whether to flush while holding the lock only briefly.
        let should_flush = {
            let mut batch = self.batch.lock().await;
            batch.push(event);
            batch.len() >= self.batch_size
        }; // lock released before any network I/O
        if should_flush {
            self.flush().await?;
        }
        Ok(())
    }

    /// Flush the current batch of events.
    pub async fn flush(&self) -> Result<(), AgentError> {
        // Take the whole batch out under the lock, then send without holding it.
        let events = {
            let mut batch = self.batch.lock().await;
            if batch.is_empty() {
                return Ok(());
            }
            std::mem::take(&mut *batch)
        }; // lock released before network I/O

        let request = ReportPodEventsRequest { events };
        // tonic clients are cheap to clone (they clone the underlying channel).
        let mut client = self.client.clone();
        match client.report_pod_events(request).await {
            Ok(_response) => {
                tracing::debug!("pod events flushed");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to flush pod events");
                Err(AgentError::Internal(format!(
                    "failed to flush pod events: {}",
                    e
                )))
            }
        }
    }

    /// Run the periodic flush loop until the shutdown signal fires.
    pub async fn run_flush_loop(
        &self,
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
