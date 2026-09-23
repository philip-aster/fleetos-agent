// SPDX-License-Identifier: Apache-2.0
//! FLOW_EVENTS ring buffer drain → OTLP push.
//!
//! The eBPF FLOW_EVENTS ring buffer is drained periodically and converted
//! to OTLP format for export. Push-only, outbound-only — consistent with
//! the dark-overlay rule. No inbound scrape endpoints.

use std::time::Duration;

use aya::maps::RingBuf;
use tokio::sync::watch;

use crate::ebpf::events::{ParsedFlowEvent, drain_events};
use crate::error::AgentError;

/// OTLP flow record for export.
#[derive(Debug, Clone)]
pub struct OtlpFlowRecord {
    pub src_fingerprint: [u8; 16],
    pub dst_fingerprint: [u8; 16],
    pub port: u16,
    pub action: u8,
    pub direction: u8,
    pub timestamp_unix: u64,
}

impl From<&ParsedFlowEvent> for OtlpFlowRecord {
    fn from(event: &ParsedFlowEvent) -> Self {
        Self {
            src_fingerprint: event.src_fingerprint,
            dst_fingerprint: event.dst_fingerprint,
            port: event.port,
            action: event.action,
            direction: event.direction,
            timestamp_unix: event.timestamp_unix,
        }
    }
}

/// Convert parsed flow events to OTLP records.
pub fn to_otlp_records(events: &[ParsedFlowEvent]) -> Vec<OtlpFlowRecord> {
    events.iter().map(OtlpFlowRecord::from).collect()
}

/// Push OTLP flow records to the OTLP endpoint.
///
/// Outbound-only. No inbound scrape endpoints.
/// TODO: Wire the actual OTLP exporter (opentelemetry-otlp).
/// For now, this is a stub that logs the records.
pub async fn push_otlp_records(records: &[OtlpFlowRecord]) -> Result<(), AgentError> {
    if records.is_empty() {
        return Ok(());
    }

    // TODO: Wire the actual OTLP exporter.
    // For now, log the records.
    tracing::debug!(count = records.len(), "OTLP flow records to push");

    Ok(())
}

/// Flow events drain loop. Periodically drains the FLOW_EVENTS ring buffer
/// and pushes OTLP records. Runs until the shutdown signal fires.
pub struct FlowEventsDrainLoop {
    ring_buf: RingBuf<aya::maps::MapData>,
    interval: Duration,
}

impl FlowEventsDrainLoop {
    pub fn new(ring_buf: RingBuf<aya::maps::MapData>, interval: Duration) -> Self {
        Self { ring_buf, interval }
    }

    /// Run the drain loop. Periodically drains the ring buffer and pushes OTLP records.
    pub async fn run_drain_loop(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), AgentError> {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("flow events drain loop shutting down");
                        return Ok(());
                    }
                }
                _ = interval.tick() => {
                    match drain_events(&mut self.ring_buf) {
                        Ok(events) => {
                            if !events.is_empty() {
                                let records = to_otlp_records(&events);
                                if let Err(e) = push_otlp_records(&records).await {
                                    tracing::warn!(error = %e, "failed to push OTLP flow records");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to drain FLOW_EVENTS");
                        }
                    }
                }
            }
        }
    }
}
