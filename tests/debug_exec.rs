// SPDX-License-Identifier: Apache-2.0
//! Phase 8.7 tests: debug tunnel frame construction, dispatch, and exec handler.
//!
//! Unit tests for frame helpers and session management. Actual exec into
//! a container requires root + containerd and is covered by gated
//! integration tests.

use fleetos_agent::debugging::DebugTunnel;
use fleetos_agent::workloads::RuntimeKind;
use fleetos_agent::workloads::pod_manager::{Pod, PodManager, PodState};
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::debug::{DebugFrame, ExecRequest};
use fleetos_core::proto::fleetos::debug_frame;
use std::sync::Arc;
use tokio::sync::RwLock;

// --- Frame construction ---

#[test]
fn ack_frame_construction() {
    let frame = DebugTunnel::ack_frame("sess-1", true, "");
    assert_eq!(frame.session_id, "sess-1");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(ack.accepted);
            assert!(ack.reject_reason.is_empty());
        }
        _ => panic!("expected Ack payload"),
    }
}

#[test]
fn ack_frame_rejection() {
    let frame = DebugTunnel::ack_frame("sess-2", false, "pod not found");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(!ack.accepted);
            assert_eq!(ack.reject_reason, "pod not found");
        }
        _ => panic!("expected Ack payload"),
    }
}

#[test]
fn data_frame_construction() {
    let frame = DebugTunnel::data_frame("sess-3", 1, b"hello stdout".to_vec());
    assert_eq!(frame.session_id, "sess-3");
    match frame.payload {
        Some(debug_frame::Payload::Data(chunk)) => {
            assert_eq!(chunk.channel, 1);
            assert_eq!(chunk.payload, b"hello stdout");
        }
        _ => panic!("expected Data payload"),
    }
}

#[test]
fn data_frame_channels() {
    // Channel 0 = stdin, 1 = stdout, 2 = stderr.
    for ch in [0u32, 1, 2] {
        let frame = DebugTunnel::data_frame("s", ch, vec![]);
        match frame.payload {
            Some(debug_frame::Payload::Data(chunk)) => {
                assert_eq!(chunk.channel, ch);
            }
            _ => panic!("expected Data payload"),
        }
    }
}

#[test]
fn end_frame_construction() {
    let frame = DebugTunnel::end_frame("sess-4", false, "");
    match frame.payload {
        Some(debug_frame::Payload::End(end)) => {
            assert!(!end.error);
            assert!(end.message.is_empty());
        }
        _ => panic!("expected End payload"),
    }

    let err_frame = DebugTunnel::end_frame("sess-5", true, "exec failed");
    match err_frame.payload {
        Some(debug_frame::Payload::End(end)) => {
            assert!(end.error);
            assert_eq!(end.message, "exec failed");
        }
        _ => panic!("expected End payload"),
    }
}

// --- Pod lookup for exec dispatch ---

fn make_pod(pod_id: &str, runtime: RuntimeKind, pid: Option<u32>) -> Pod {
    let mut pod = Pod::new(
        pod_id.to_string(),
        "test-workload".to_string(),
        "test-tenant".to_string(),
        "primary".to_string(),
        runtime,
        IdentityFingerprint([0u8; 16]),
    );
    pod.state = PodState::Running;
    pod.pid = pid;
    pod
}

#[tokio::test]
async fn exec_rejects_missing_pod() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<DebugFrame>(16);
    let stdin_router: fleetos_agent::debugging::StdinRouter =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let req = ExecRequest {
        command: vec!["echo".to_string(), "hello".to_string()],
        tty: false,
        stdin: false,
    };

    fleetos_agent::debugging::exec::handle_exec(
        "sess-1".to_string(),
        "nonexistent-pod".to_string(),
        req,
        tx,
        stdin_router,
        pm,
    )
    .await;

    let frame = rx.recv().await.expect("should receive a frame");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(!ack.accepted);
            assert!(ack.reject_reason.contains("not found"));
        }
        _ => panic!("expected Ack payload"),
    }
}

#[tokio::test]
async fn exec_rejects_pod_without_pid() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("pod-1", RuntimeKind::Containerd, None));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<DebugFrame>(16);
    let stdin_router: fleetos_agent::debugging::StdinRouter =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let req = ExecRequest {
        command: vec!["echo".to_string()],
        tty: false,
        stdin: false,
    };

    fleetos_agent::debugging::exec::handle_exec(
        "sess-2".to_string(),
        "pod-1".to_string(),
        req,
        tx,
        stdin_router,
        pm,
    )
    .await;

    let frame = rx.recv().await.expect("should receive a frame");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(!ack.accepted);
            assert!(ack.reject_reason.contains("no running process"));
        }
        _ => panic!("expected Ack payload"),
    }
}

#[tokio::test]
async fn exec_rejects_microvm_pod() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("pod-vm", RuntimeKind::CloudHypervisor, Some(42)));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<DebugFrame>(16);
    let stdin_router: fleetos_agent::debugging::StdinRouter =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let req = ExecRequest {
        command: vec!["ls".to_string()],
        tty: false,
        stdin: false,
    };

    fleetos_agent::debugging::exec::handle_exec(
        "sess-3".to_string(),
        "pod-vm".to_string(),
        req,
        tx,
        stdin_router,
        pm,
    )
    .await;

    let frame = rx.recv().await.expect("should receive a frame");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(!ack.accepted);
            assert!(ack.reject_reason.contains("MicroVM not supported"));
        }
        _ => panic!("expected Ack payload"),
    }
}

#[tokio::test]
async fn exec_rejects_empty_command() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("pod-2", RuntimeKind::Containerd, Some(1234)));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<DebugFrame>(16);
    let stdin_router: fleetos_agent::debugging::StdinRouter =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let req = ExecRequest {
        command: vec![],
        tty: false,
        stdin: false,
    };

    fleetos_agent::debugging::exec::handle_exec(
        "sess-4".to_string(),
        "pod-2".to_string(),
        req,
        tx,
        stdin_router,
        pm,
    )
    .await;

    let frame = rx.recv().await.expect("should receive a frame");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(!ack.accepted);
            assert!(ack.reject_reason.contains("empty command"));
        }
        _ => panic!("expected Ack payload"),
    }
}

// --- Logs handler ---

#[tokio::test]
async fn logs_rejects_microvm_pod() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("pod-vm", RuntimeKind::CloudHypervisor, Some(42)));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<DebugFrame>(16);

    let req = fleetos_core::proto::debug::LogsRequest {
        container: String::new(),
        tail_lines: 10,
        follow: false,
        timestamps: false,
    };

    fleetos_agent::debugging::logs::handle_logs(
        "sess-5".to_string(),
        "pod-vm".to_string(),
        req,
        tx,
        pm,
        "fleetos".to_string(),
    )
    .await;

    let frame = rx.recv().await.expect("should receive a frame");
    match frame.payload {
        Some(debug_frame::Payload::Ack(ack)) => {
            assert!(!ack.accepted);
            assert!(ack.reject_reason.contains("MicroVM not supported"));
        }
        _ => panic!("expected Ack payload"),
    }
}

// --- Port-forward handler ---

#[tokio::test]
async fn port_forward_v1_stub() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("pod-3", RuntimeKind::Containerd, Some(5678)));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<DebugFrame>(16);

    let req = fleetos_core::proto::debug::PortForwardRequest { target_port: 8080 };

    fleetos_agent::debugging::port_forward::handle_port_forward(
        "sess-6".to_string(),
        "pod-3".to_string(),
        req,
        tx,
        pm,
    )
    .await;

    // Should receive ack (accepted) then end (not implemented).
    let ack = rx.recv().await.expect("should receive ack");
    match ack.payload {
        Some(debug_frame::Payload::Ack(a)) => assert!(a.accepted),
        _ => panic!("expected Ack"),
    }

    let end = rx.recv().await.expect("should receive end");
    match end.payload {
        Some(debug_frame::Payload::End(e)) => {
            assert!(!e.error);
            assert!(e.message.contains("not yet implemented"));
        }
        _ => panic!("expected End"),
    }
}
