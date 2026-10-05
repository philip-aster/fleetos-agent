// SPDX-License-Identifier: Apache-2.0
//! FLOW_EVENTS ring buffer drain → OTLP push.
//!
//! The eBPF FLOW_EVENTS ring buffer is drained periodically and converted
//! to OTLP log records for export. Push-only, outbound-only — consistent
//! with the dark-overlay rule. No inbound scrape endpoints.
use crate::ebpf::events::{ParsedFlowEvent, drain_events};
use crate::error::AgentError;
use aya::maps::{MapData, RingBuf};
use opentelemetry::Key;
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider as _, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use std::time::Duration;
use tokio::sync::watch;

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

/// OTLP log exporter for flow events.
///
/// Wraps an `opentelemetry_sdk::logs::SdkLoggerProvider` configured with an
/// OTLP gRPC exporter. Flow events are emitted as OTLP log records with
/// structured attributes. Push-only, outbound-only.
pub struct FlowOtlpExporter {
    provider: SdkLoggerProvider,
}

impl FlowOtlpExporter {
    /// Create a new OTLP flow exporter pointing at the given endpoint.
    ///
    /// The endpoint should be an OTLP gRPC endpoint, e.g.,
    /// `"http://otel-collector:4317"`.
    pub fn new(endpoint: &str) -> Result<Self, AgentError> {
        let exporter = LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| AgentError::Config(format!("OTLP exporter init failed: {}", e)))?;

        let provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter)
            .build();

        Ok(Self { provider })
    }

    /// Export a batch of flow records as OTLP log records.
    ///
    /// Each `OtlpFlowRecord` becomes an OTLP log record with structured
    /// attributes. Records are batched and flushed to the OTLP endpoint.
    pub fn export(&self, records: &[OtlpFlowRecord]) -> Result<(), AgentError> {
        if records.is_empty() {
            return Ok(());
        }

        let logger = self.provider.logger("fleetos.flow_events");

        for record in records {
            let mut log_record = logger.create_log_record();

            // Set the body to a human-readable summary.
            let body = format!(
                "flow: {} -> {}:{} action={} direction={}",
                hex::encode(record.src_fingerprint),
                hex::encode(record.dst_fingerprint),
                record.port,
                if record.action == 1 { "allow" } else { "deny" },
                if record.direction == 0 {
                    "ingress"
                } else {
                    "egress"
                }
            );
            log_record.set_body(body.into());
            log_record.set_severity_number(Severity::Info);
            log_record.set_timestamp(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(record.timestamp_unix),
            );

            // Structured attributes for querying/filtering.
            log_record.add_attributes(vec![
                (
                    Key::from_static_str("flow.src_fingerprint"),
                    AnyValue::from(hex::encode(record.src_fingerprint)),
                ),
                (
                    Key::from_static_str("flow.dst_fingerprint"),
                    AnyValue::from(hex::encode(record.dst_fingerprint)),
                ),
                (
                    Key::from_static_str("flow.port"),
                    AnyValue::from(record.port as i64),
                ),
                (
                    Key::from_static_str("flow.action"),
                    AnyValue::from(if record.action == 1 { "allow" } else { "deny" }),
                ),
                (
                    Key::from_static_str("flow.direction"),
                    AnyValue::from(if record.direction == 0 {
                        "ingress"
                    } else {
                        "egress"
                    }),
                ),
                (
                    Key::from_static_str("flow.timestamp_unix"),
                    AnyValue::from(record.timestamp_unix as i64),
                ),
            ]);

            logger.emit(log_record);
        }

        // Force flush to ensure records are sent before the drain loop exits.
        self.provider
            .force_flush()
            .map_err(|e| AgentError::Config(format!("OTLP flush failed: {}", e)))?;

        Ok(())
    }
}

/// Flow events drain loop. Periodically drains the FLOW_EVENTS ring buffer
/// and pushes OTLP records via the configured exporter.
pub struct FlowEventsDrainLoop {
    ring_buf: RingBuf<MapData>,
    interval: Duration,
    exporter: Option<FlowOtlpExporter>,
}

impl FlowEventsDrainLoop {
    pub fn new(
        ring_buf: RingBuf<MapData>,
        interval: Duration,
        exporter: Option<FlowOtlpExporter>,
    ) -> Self {
        Self {
            ring_buf,
            interval,
            exporter,
        }
    }

    /// Run the drain loop. Periodically drains the ring buffer and pushes
    /// OTLP records via the configured exporter.
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
                                if let Some(ref exporter) = self.exporter {
                                    if let Err(e) = exporter.export(&records) {
                                        tracing::warn!(error = %e, "failed to push OTLP flow records");
                                    }
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
