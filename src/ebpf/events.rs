// SPDX-License-Identifier: Apache-2.0
//! FLOW_EVENTS ring buffer drain.
//!
//! The kernel writes `FlowEvent` structs to the FLOW_EVENTS ring buffer.
//! The agent drains them periodically and converts to the agent's internal
//! FlowEvent representation for observability export (Batch 11).
//!
//! The ring buffer is 1MB. If the agent falls behind, events are dropped
//! by the kernel (best-effort telemetry). The agent must drain fast enough
//! to keep up, but a full ring buffer must never block the datapath.

use crate::error::AgentError;
use aya::Ebpf;
use aya::maps::RingBuf;
use fleetos_ebpf_common::FlowEvent;
use std::time::{SystemTime, UNIX_EPOCH};

/// Take the FLOW_EVENTS ring buffer from the eBPF object.
pub fn take_flow_events_ringbuf(
    ebpf: &mut Ebpf,
) -> Result<RingBuf<aya::maps::MapData>, AgentError> {
    let map = ebpf
        .take_map("FLOW_EVENTS")
        .ok_or_else(|| AgentError::Ebpf("FLOW_EVENTS missing".into()))?;
    RingBuf::try_from(map).map_err(|e| AgentError::Ebpf(format!("FLOW_EVENTS: {}", e)))
}

/// Parsed flow event from the ring buffer.
#[derive(Debug, Clone)]
pub struct ParsedFlowEvent {
    pub src_fingerprint: [u8; 16],
    pub dst_fingerprint: [u8; 16],
    pub port: u16,
    pub action: u8,    // 0 = deny, 1 = allow
    pub direction: u8, // 0 = ingress, 1 = egress
    pub timestamp_unix: u64,
}

impl From<&FlowEvent> for ParsedFlowEvent {
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Drain all pending events from the ring buffer.
///
/// Returns a vector of parsed events. Non-blocking: returns immediately
/// with whatever is available.
pub fn drain_events(
    ring_buf: &mut RingBuf<aya::maps::MapData>,
) -> Result<Vec<ParsedFlowEvent>, AgentError> {
    let mut events = Vec::new();

    while let Some(item) = ring_buf.next() {
        let bytes: &[u8] = &item;
        if bytes.len() < std::mem::size_of::<FlowEvent>() {
            tracing::warn!(
                len = bytes.len(),
                expected = std::mem::size_of::<FlowEvent>(),
                "FLOW_EVENTS: truncated event, skipping"
            );
            continue;
        }
        let event: &FlowEvent = bytemuck::from_bytes(&bytes[..std::mem::size_of::<FlowEvent>()]);
        events.push(ParsedFlowEvent::from(event));
    }

    Ok(events)
}
