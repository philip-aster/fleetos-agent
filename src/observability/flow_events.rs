// SPDX-License-Identifier: Apache-2.0
//! FLOW_EVENTS ring buffer drain → OTLP push.
//!
//! The eBPF FLOW_EVENTS ring buffer is drained periodically and converted
//! to OTLP format for export. Push-only, no inbound scrape.

use aya::maps::RingBuf;

use fleetos_ebpf_common::FlowEvent;

/// OTLP flow record.
#[derive(Debug, Clone)]
pub struct OtlpFlowRecord {
    pub src_fingerprint: [u8; 16],
    pub dst_fingerprint: [u8; 16],
    pub port: u16,
    pub action: u8,
    pub direction: u8,
    pub timestamp_unix: u64,
}

impl From<&FlowEvent> for OtlpFlowRecord {
    fn from(event: &FlowEvent) -> Self {
        Self {
            src_fingerprint: event.src_hash.0,
            dst_fingerprint: event.dst_hash.0,
            port: event.port.0,
            action: event.action,
            direction: event.direction,
            timestamp_unix: now_unix(),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Drain FLOW_EVENTS ring buffer and convert to OTLP records.
pub fn drain_flow_events(_ring_buf: &mut RingBuf<aya::maps::MapData>) -> Vec<OtlpFlowRecord> {
    let records = Vec::new();

    // TODO: Implement ring buffer drain.
    // The ring buffer contains FlowEvent structs.
    // Drain all available events and convert to OTLP format.

    records
}
