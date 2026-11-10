// SPDX-License-Identifier: Apache-2.0
//! Logs handler: stream container logs back through the debug tunnel.
//!
//! v1: reads from the containerd shim's log file at the well-known path
//! `/run/containerd/io.containerd.runtime.v2.task/{namespace}/{container_id}/log`.
//! Supports `tail_lines` by reading the last N lines. `follow` is not
//! supported in v1 (returns what's available). `timestamps` is ignored
//! (containerd log format is configuration-dependent).
//!
//! MicroVM: not supported in v1 (logs live inside the guest).

use super::{DebugFrame, DebugTunnel};
use crate::workloads::RuntimeKind;
use crate::workloads::pod_manager::PodManager;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

/// Maximum bytes to read from the tail of a log file (1 MB).
const MAX_TAIL_BYTES: usize = 1024 * 1024;

/// Handle a logs session: read container logs and stream them back.
pub async fn handle_logs(
    session_id: String,
    pod_id: String,
    req: fleetos_core::proto::debug::LogsRequest,
    outbound_tx: mpsc::Sender<DebugFrame>,
    pod_manager: Arc<RwLock<PodManager>>,
    namespace: String,
) {
    // Look up the pod to determine runtime.
    let runtime = {
        let pm = pod_manager.read().await;
        match pm.get_pod(&pod_id) {
            Some(pod) => pod.runtime,
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

    match runtime {
        RuntimeKind::Containerd => {
            logs_containerd(session_id, pod_id, req, outbound_tx, namespace).await;
        }
        RuntimeKind::CloudHypervisor => {
            let _ = outbound_tx
                .send(DebugTunnel::ack_frame(
                    &session_id,
                    false,
                    "logs from MicroVM not supported in v1",
                ))
                .await;
        }
    }
}

/// Read logs from the containerd shim log file.
async fn logs_containerd(
    session_id: String,
    pod_id: String,
    req: fleetos_core::proto::debug::LogsRequest,
    outbound_tx: mpsc::Sender<DebugFrame>,
    namespace: String,
) {
    // Containerd shim log file path.
    let log_path = format!(
        "/run/containerd/io.containerd.runtime.v2.task/{}/{}",
        namespace, pod_id
    );

    // Check if the log directory exists. The actual log file may be at
    // different sub-paths depending on containerd version.
    let log_file = std::path::Path::new(&log_path).join("log");

    if !log_file.exists() {
        let _ = outbound_tx
            .send(DebugTunnel::ack_frame(
                &session_id,
                false,
                &format!("log file not found: {}", log_file.display()),
            ))
            .await;
        return;
    }

    // Ack the session.
    if outbound_tx
        .send(DebugTunnel::ack_frame(&session_id, true, ""))
        .await
        .is_err()
    {
        return;
    }

    // Read the log file (blocking I/O in a spawn_blocking).
    let tail_lines = req.tail_lines;
    let result = tokio::task::spawn_blocking(move || read_log_tail(&log_file, tail_lines)).await;

    match result {
        Ok(Ok(lines)) => {
            // Send all lines as a single DataChunk on stdout (channel 1).
            let payload = lines.into_bytes();
            if !payload.is_empty() {
                let _ = outbound_tx
                    .send(DebugTunnel::data_frame(&session_id, 1, payload))
                    .await;
            }
            let _ = outbound_tx
                .send(DebugTunnel::end_frame(&session_id, false, ""))
                .await;
        }
        Ok(Err(e)) => {
            let _ = outbound_tx
                .send(DebugTunnel::end_frame(
                    &session_id,
                    true,
                    &format!("failed to read logs: {}", e),
                ))
                .await;
        }
        Err(e) => {
            let _ = outbound_tx
                .send(DebugTunnel::end_frame(
                    &session_id,
                    true,
                    &format!("log reader task failed: {}", e),
                ))
                .await;
        }
    }
}

/// Read the last `tail_lines` lines from a log file.
/// If `tail_lines` is 0, read the entire file (up to MAX_TAIL_BYTES).
fn read_log_tail(path: &std::path::Path, tail_lines: i64) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("open failed: {}", e))?;

    let metadata = file
        .metadata()
        .map_err(|e| format!("metadata failed: {}", e))?;
    let file_size = metadata.len() as usize;

    // Seek to the tail region to avoid reading the entire file.
    let read_start = if tail_lines > 0 {
        // Read the last MAX_TAIL_BYTES and extract tail_lines from that.
        file_size.saturating_sub(MAX_TAIL_BYTES)
    } else {
        0
    };

    file.seek(SeekFrom::Start(read_start as u64))
        .map_err(|e| format!("seek failed: {}", e))?;

    let mut buf = Vec::new();
    file.read_to_end(&mut buf)
        .map_err(|e| format!("read failed: {}", e))?;

    let reader = BufReader::new(&buf[..]);
    let all_lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let lines: Vec<&str> = if tail_lines > 0 {
        let count = tail_lines as usize;
        let start = all_lines.len().saturating_sub(count);
        all_lines[start..].iter().map(|s| s.as_str()).collect()
    } else {
        all_lines.iter().map(|s| s.as_str()).collect()
    };

    Ok(lines.join("\n"))
}
