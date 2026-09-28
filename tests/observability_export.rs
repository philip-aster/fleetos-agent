// SPDX-License-Identifier: Apache-2.0
//! Phase 6.7 — Observability export (flow events, pod events, metrics).
//!
//! Covers the testable observability export paths against the REAL API:
//! - Flow events: ParsedFlowEvent → OtlpFlowRecord conversion (`to_otlp_records`),
//!   plus the `From<&FlowEvent>` conversion that feeds it.
//! - Pod events: canonical event-type vocabulary (CR-CTRL-7), and batched
//!   `record_event` → `flush` over a real gRPC `PodEventService` (mock server).
//! - Metrics: aggregate/rate logic is covered by `tests/counters_rate.rs`.
//!
//! The RingBuf drain loop (`drain_events`) and the OTLP push stub are not
//! exercised here (they need a loaded eBPF object / a real OTLP collector).

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleetos_agent::ebpf::events::ParsedFlowEvent;
use fleetos_agent::observability::flow_events::to_otlp_records;
use fleetos_agent::observability::pod_events::{PodEventReporter, event_types};
use fleetos_core::proto::fleetos::{
    PodEvent, ReportPodEventsRequest, ReportPodEventsResponse, WatchPodEventsRequest,
    pod_event_service_client::PodEventServiceClient,
    pod_event_service_server::{PodEventService, PodEventServiceServer},
};
use fleetos_ebpf_common::{FlowEvent, HostOrderPort, IdentityFingerprint};
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

// ---------------------------------------------------------------------------
// Flow events: ParsedFlowEvent → OtlpFlowRecord conversion
// ---------------------------------------------------------------------------

fn make_parsed_event(
    src: [u8; 16],
    dst: [u8; 16],
    port: u16,
    action: u8,
    direction: u8,
    ts: u64,
) -> ParsedFlowEvent {
    ParsedFlowEvent {
        src_fingerprint: src,
        dst_fingerprint: dst,
        port,
        action,
        direction,
        timestamp_unix: ts,
    }
}

#[test]
fn to_otlp_records_maps_all_fields() {
    let events = vec![
        make_parsed_event([1; 16], [2; 16], 8080, 1, 0, 100),
        make_parsed_event([3; 16], [4; 16], 443, 0, 1, 200),
    ];
    let records = to_otlp_records(&events);
    assert_eq!(records.len(), 2);

    let r0 = &records[0];
    assert_eq!(r0.src_fingerprint, [1; 16]);
    assert_eq!(r0.dst_fingerprint, [2; 16]);
    assert_eq!(r0.port, 8080);
    assert_eq!(r0.action, 1);
    assert_eq!(r0.direction, 0);
    assert_eq!(r0.timestamp_unix, 100);

    let r1 = &records[1];
    assert_eq!(r1.src_fingerprint, [3; 16]);
    assert_eq!(r1.dst_fingerprint, [4; 16]);
    assert_eq!(r1.port, 443);
    assert_eq!(r1.action, 0);
    assert_eq!(r1.direction, 1);
    assert_eq!(r1.timestamp_unix, 200);
}

#[test]
fn to_otlp_records_empty_input_gives_empty_output() {
    let records = to_otlp_records(&[]);
    assert!(records.is_empty());
}

#[test]
fn parsed_flow_event_from_kernel_flow_event() {
    // The kernel writes `FlowEvent`; the drain loop converts via `From<&FlowEvent>`.
    // Verify fingerprints, host-order port, action, and direction survive.
    let fe = FlowEvent {
        src_hash: IdentityFingerprint([5; 16]),
        dst_hash: IdentityFingerprint([6; 16]),
        port: HostOrderPort(9090), // host-order port
        action: 1,
        direction: 0,
        _pad: [0; 4],
    };
    let parsed = ParsedFlowEvent::from(&fe);
    assert_eq!(parsed.src_fingerprint, [5; 16]);
    assert_eq!(parsed.dst_fingerprint, [6; 16]);
    assert_eq!(parsed.port, 9090);
    assert_eq!(parsed.action, 1);
    assert_eq!(parsed.direction, 0);
    assert!(parsed.timestamp_unix > 0, "timestamp must be populated");
}

// ---------------------------------------------------------------------------
// Pod events: canonical vocabulary (CR-CTRL-7)
// ---------------------------------------------------------------------------

#[test]
fn pod_event_vocabulary_is_canonical() {
    // Lock the canonical event-type vocabulary. These values are the contract
    // between agent and control; control-side coalescing keys on them.
    assert_eq!(event_types::PULLED, "Pulled");
    assert_eq!(event_types::CREATED, "Created");
    assert_eq!(event_types::STARTED, "Started");
    assert_eq!(event_types::PROBE_FAILED, "ProbeFailed");
    assert_eq!(event_types::BACK_OFF, "BackOff");
    assert_eq!(event_types::OOM_KILLED, "OOMKilled");
    assert_eq!(event_types::EVICTING, "Evicting");
    assert_eq!(event_types::GRACE_PERIOD_EXPIRED, "GracePeriodExpired");
    assert_eq!(event_types::FAILED_SCHEDULING, "FailedScheduling");
    assert_eq!(event_types::RESIZING, "Resizing");
    assert_eq!(event_types::RESIZED, "Resized");
}

// ---------------------------------------------------------------------------
// Pod events: batched record_event → flush over a mock PodEventService
// ---------------------------------------------------------------------------

struct MockPodEventService {
    received: Arc<Mutex<Vec<ReportPodEventsRequest>>>,
}

#[tonic::async_trait]
impl PodEventService for MockPodEventService {
    async fn report_pod_events(
        &self,
        request: Request<ReportPodEventsRequest>,
    ) -> Result<Response<ReportPodEventsResponse>, Status> {
        self.received.lock().unwrap().push(request.into_inner());
        Ok(Response::new(ReportPodEventsResponse {}))
    }

    type WatchPodEventsStream =
        Pin<Box<dyn futures::Stream<Item = Result<PodEvent, Status>> + Send + 'static>>;

    async fn watch_pod_events(
        &self,
        _request: Request<WatchPodEventsRequest>,
    ) -> Result<Response<Self::WatchPodEventsStream>, Status> {
        Ok(Response::new(Box::pin(futures::stream::empty())))
    }
}

async fn spawn_pod_event_server() -> (String, Arc<Mutex<Vec<ReportPodEventsRequest>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let received = Arc::new(Mutex::new(Vec::new()));
    let svc = MockPodEventService {
        received: received.clone(),
    };
    tokio::spawn(async move {
        Server::builder()
            .add_service(PodEventServiceServer::new(svc))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    // Give the server a beat to start accepting.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr.to_string(), received)
}

#[tokio::test]
async fn pod_events_batch_and_flush() {
    let (addr, received) = spawn_pod_event_server().await;
    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = PodEventServiceClient::new(channel);

    // batch_size 100 → recording 2 events does NOT auto-flush.
    let mut reporter =
        PodEventReporter::new("node-1".to_string(), client, 100, Duration::from_secs(60));

    reporter
        .record_event("pod-1", event_types::STARTED, "", "")
        .await
        .unwrap();
    reporter
        .record_event("pod-1", event_types::BACK_OFF, "CrashLoop", "restarting")
        .await
        .unwrap();

    // Nothing flushed yet.
    assert!(
        received.lock().unwrap().is_empty(),
        "no flush should have happened before explicit flush"
    );

    reporter.flush().await.unwrap();

    let received = received.lock().unwrap();
    assert_eq!(received.len(), 1, "exactly one ReportPodEvents call");
    let req = &received[0];
    assert_eq!(req.events.len(), 2);

    let e0 = &req.events[0];
    assert_eq!(e0.pod_id, "pod-1");
    assert_eq!(e0.node_id, "node-1");
    assert_eq!(e0.event_type, event_types::STARTED);
    assert_eq!(e0.count, 1);

    let e1 = &req.events[1];
    assert_eq!(e1.event_type, event_types::BACK_OFF);
    assert_eq!(e1.reason, "CrashLoop");
    assert_eq!(e1.message, "restarting");
}

#[tokio::test]
async fn pod_events_auto_flush_when_batch_full() {
    let (addr, received) = spawn_pod_event_server().await;
    let channel = Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let client = PodEventServiceClient::new(channel);

    // batch_size 2 → the second record_event triggers an automatic flush.
    let mut reporter =
        PodEventReporter::new("node-2".to_string(), client, 2, Duration::from_secs(60));

    reporter
        .record_event("pod-a", event_types::CREATED, "", "")
        .await
        .unwrap();
    // Still under batch size → nothing flushed.
    assert!(received.lock().unwrap().is_empty());

    reporter
        .record_event("pod-a", event_types::STARTED, "", "")
        .await
        .unwrap();

    // Auto-flush should have fired.
    let received = received.lock().unwrap();
    assert_eq!(received.len(), 1, "auto-flush should have fired");
    assert_eq!(received[0].events.len(), 2);
    assert_eq!(received[0].events[0].event_type, event_types::CREATED);
    assert_eq!(received[0].events[1].event_type, event_types::STARTED);
}
