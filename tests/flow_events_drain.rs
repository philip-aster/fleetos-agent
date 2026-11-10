// SPDX-License-Identifier: Apache-2.0
//! Phase 8.8: FlowEventsDrainLoop and OTLP export supplementary tests.
//!
//! to_otlp_records and the pod event vocabulary are covered by
//! observability_export.rs. This file adds edge cases for the conversion
//! and verifies the FlowOtlpExporter constructor.
//!
//! The RingBuf drain loop requires a loaded eBPF object (gated).
//! The OTLP push requires a running collector (gated in observability_export.rs).
use fleetos_agent::ebpf::events::ParsedFlowEvent;
use fleetos_agent::observability::flow_events::to_otlp_records;
use fleetos_ebpf_common::{FlowEvent, HostOrderPort, IdentityFingerprint};

fn make_event(src: u8, dst: u8, port: u16, action: u8, direction: u8) -> ParsedFlowEvent {
    ParsedFlowEvent {
        src_fingerprint: [src; 16],
        dst_fingerprint: [dst; 16],
        port,
        action,
        direction,
        timestamp_unix: 1_700_000_000,
    }
}

#[test]
fn to_otlp_records_preserves_all_fields() {
    let events = vec![make_event(0xAA, 0xBB, 8080, 1, 0)];
    let records = to_otlp_records(&events);
    assert_eq!(records.len(), 1);
    let r = &records[0];
    assert_eq!(r.src_fingerprint, [0xAA; 16]);
    assert_eq!(r.dst_fingerprint, [0xBB; 16]);
    assert_eq!(r.port, 8080);
    assert_eq!(r.action, 1);
    assert_eq!(r.direction, 0);
    assert_eq!(r.timestamp_unix, 1_700_000_000);
}

#[test]
fn to_otlp_records_batch() {
    let events: Vec<ParsedFlowEvent> = (0..100)
        .map(|i| make_event(i as u8, (i + 1) as u8, 80 + i as u16, (i % 2) as u8, 0))
        .collect();
    let records = to_otlp_records(&events);
    assert_eq!(records.len(), 100);
}

#[test]
fn parsed_flow_event_from_kernel_preserves_port() {
    let fe = FlowEvent {
        src_hash: IdentityFingerprint([1; 16]),
        dst_hash: IdentityFingerprint([2; 16]),
        port: HostOrderPort(443),
        action: 0,
        direction: 1,
        _pad: [0; 4],
    };
    let parsed = ParsedFlowEvent::from(&fe);
    assert_eq!(parsed.port, 443);
    assert_eq!(parsed.action, 0);
    assert_eq!(parsed.direction, 1);
    assert!(parsed.timestamp_unix > 0);
}

#[tokio::test]
async fn flow_otlp_exporter_rejects_empty_endpoint() {
    // An empty endpoint should fail construction (no valid URI).
    let result = fleetos_agent::observability::flow_events::FlowOtlpExporter::new("");
    assert!(result.is_err(), "empty OTLP endpoint must be rejected");
}

#[tokio::test]
async fn flow_otlp_exporter_accepts_valid_endpoint() {
    // Construction with a syntactically valid endpoint succeeds
    // (connection is lazy — no collector needed).
    let result =
        fleetos_agent::observability::flow_events::FlowOtlpExporter::new("http://localhost:4317");
    assert!(result.is_ok(), "valid OTLP endpoint must be accepted");
}
