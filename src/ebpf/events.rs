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
}

/// Drain all pending events from the ring buffer.
///
/// Returns a vector of parsed events. Non-blocking: returns immediately
/// with whatever is available.
///
/// TODO(Batch 11): Wire the actual Aya 0.14 RingBuf drain loop.
/// Aya 0.14's RingBuf requires epoll/poll integration for async draining
/// rather than a simple synchronous callback. For Batch 4, we provide
/// the structural boundary and parsing logic only. The actual drain loop
/// will be implemented when we wire the observability subsystem.
pub fn drain_events(
    _ring_buf: &mut RingBuf<aya::maps::MapData>,
) -> Result<Vec<ParsedFlowEvent>, AgentError> {
    // Stub: return empty vector. Actual drain logic lands in Batch 11.
    Ok(Vec::new())
}
