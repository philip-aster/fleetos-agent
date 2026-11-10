// SPDX-License-Identifier: Apache-2.0
//! Exec handler: run a command in a container/VM, stream stdin/stdout/stderr.
//!
//! Channel convention (K8s streaming): 0=stdin, 1=stdout, 2=stderr.
//!
//! Containerd: uses `nsenter` to enter the container's namespaces and run
//! the command. The agent runs as root on the host, so nsenter is available.
//! The container's task PID is stored in `Pod.pid` at boot time.
//!
//! MicroVM: not supported in v1. Would require a VSOCK-based exec protocol
//! with guest-init cooperation. Returns a reject ack.

use super::{DebugFrame, DebugTunnel, StdinRouter};
use crate::workloads::RuntimeKind;
use crate::workloads::pod_manager::PodManager;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{RwLock, mpsc};

/// Read buffer size for stdout/stderr streaming (8 KB per chunk).
const READ_BUF_SIZE: usize = 8192;

/// Handle an exec session: run a command in a container/VM and stream I/O.
pub async fn handle_exec(
    session_id: String,
    pod_id: String,
    req: fleetos_core::proto::debug::ExecRequest,
    outbound_tx: mpsc::Sender<DebugFrame>,
    stdin_router: StdinRouter,
    pod_manager: Arc<RwLock<PodManager>>,
) {
    // Look up the pod to get runtime and PID.
    let (runtime, pid) = {
        let pm = pod_manager.read().await;
        match pm.get_pod(&pod_id) {
            Some(pod) => (pod.runtime, pod.pid),
            None => {
                let _ = outbound_tx
                    .send(DebugTunnel::ack_frame(
                        &session_id,
                        false,
                        &format!("pod '{}' not found", pod_id),
                    ))
                    .await;
                return;
            }
        }
    };

    let pid = match pid {
        Some(p) if p > 0 => p,
        _ => {
            let _ = outbound_tx
                .send(DebugTunnel::ack_frame(
                    &session_id,
                    false,
                    "pod has no running process",
                ))
                .await;
            return;
        }
    };

    match runtime {
        RuntimeKind::Containerd => {
            exec_containerd(session_id, pid, req, outbound_tx, stdin_router).await;
        }
        RuntimeKind::CloudHypervisor => {
            let _ = outbound_tx
                .send(DebugTunnel::ack_frame(
                    &session_id,
                    false,
                    "exec into MicroVM not supported in v1",
                ))
                .await;
        }
    }
}

/// Exec into a containerd container via nsenter.
///
/// Enters the container's mount, PID, network, UTS, and IPC namespaces
/// and runs the requested command. Streams stdout/stderr back as DataChunk
/// messages and pipes stdin DataChunks to the process.
async fn exec_containerd(
    session_id: String,
    pid: u32,
    req: fleetos_core::proto::debug::ExecRequest,
    outbound_tx: mpsc::Sender<DebugFrame>,
    stdin_router: StdinRouter,
) {
    if req.command.is_empty() {
        let _ = outbound_tx
            .send(DebugTunnel::ack_frame(&session_id, false, "empty command"))
            .await;
        return;
    }

    // Build nsenter command: enter all container namespaces.
    let mut cmd = tokio::process::Command::new("nsenter");
    cmd.arg("-t")
        .arg(pid.to_string())
        .arg("-m") // mount namespace
        .arg("-p") // PID namespace
        .arg("-n") // network namespace
        .arg("-u") // UTS namespace
        .arg("-i") // IPC namespace
        .arg("--")
        .args(&req.command);

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    if req.stdin {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = outbound_tx
                .send(DebugTunnel::ack_frame(
                    &session_id,
                    false,
                    &format!("failed to spawn exec: {}", e),
                ))
                .await;
            return;
        }
    };

    // Ack the session.
    if outbound_tx
        .send(DebugTunnel::ack_frame(&session_id, true, ""))
        .await
        .is_err()
    {
        let _ = child.kill().await;
        return;
    }

    // Set up stdin routing if the operator wants interactive input.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
    if req.stdin {
        stdin_router
            .lock()
            .await
            .insert(session_id.clone(), stdin_tx);
    }

    // Take ownership of the child's I/O handles.
    let mut child_stdin = child.stdin.take();
    let child_stdout = child.stdout.take();
    let child_stderr = child.stderr.take();

    let sid = session_id.clone();

    // Task: read stdout → DataChunk(channel=1).
    let stdout_handle = child_stdout.map(|stdout| {
        let sid = sid.clone();
        let tx = outbound_tx.clone();
        tokio::spawn(async move {
            let mut reader = stdout;
            let mut buf = vec![0u8; READ_BUF_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let frame = DebugTunnel::data_frame(&sid, 1, buf[..n].to_vec());
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    });

    // Task: read stderr → DataChunk(channel=2).
    let stderr_handle = child_stderr.map(|stderr| {
        let sid = sid.clone();
        let tx = outbound_tx.clone();
        tokio::spawn(async move {
            let mut reader = stderr;
            let mut buf = vec![0u8; READ_BUF_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        let frame = DebugTunnel::data_frame(&sid, 2, buf[..n].to_vec());
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })
    });

    // Task: pipe stdin DataChunks to the process.
    let stdin_handle = if req.stdin {
        let sid = session_id.clone();
        Some(tokio::spawn(async move {
            while let Some(data) = stdin_rx.recv().await {
                if let Some(ref mut stdin) = child_stdin {
                    if stdin.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = stdin.flush().await;
                }
            }
            // Dropping child_stdin closes the process's stdin.
            let _ = &sid;
        }))
    } else {
        None
    };

    // Wait for the process to exit.
    let exit_status = child.wait().await;

    // Wait for I/O tasks to drain.
    if let Some(h) = stdout_handle {
        let _ = h.await;
    }
    if let Some(h) = stderr_handle {
        let _ = h.await;
    }
    if let Some(h) = stdin_handle {
        let _ = h.await;
    }

    // Clean up stdin routing.
    stdin_router.lock().await.remove(&session_id);

    // Send SessionEnd with exit info.
    let (error, message) = match exit_status {
        Ok(status) if status.success() => (false, String::new()),
        Ok(status) => (false, format!("exit code: {:?}", status.code())),
        Err(e) => (true, format!("exec error: {}", e)),
    };
    let _ = outbound_tx
        .send(DebugTunnel::end_frame(&session_id, error, &message))
        .await;
}
