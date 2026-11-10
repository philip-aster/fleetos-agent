// SPDX-License-Identifier: Apache-2.0
//! Debug tunnel — agent-side client leg of AgentDebugService (Phase 8.7).
//!
//! The agent opens a long-lived bidi gRPC stream to control's
//! `AgentDebugService.AgentConnect`. Control multiplexes operator debug
//! sessions onto this stream. The agent dispatches SessionStart/DataChunk/
//! SessionEnd frames to the appropriate handler and streams results back.
//!
//! This is a REVERSE tunnel: the agent initiates the connection outward
//! (dark overlay — no inbound connections), and control sends commands
//! back through the established stream.
//!
//! Reconnect: exponential backoff from BASE_RETRY_DELAY_MS to
//! MAX_RETRY_DELAY_MS, mirroring the watch-stream pattern in
//! `client/watch.rs`.

pub mod exec;
pub mod logs;
pub mod port_forward;

use crate::client::ControlPlaneClient;
use crate::client::retry::{BASE_RETRY_DELAY_MS, MAX_RETRY_DELAY_MS};
use crate::error::AgentError;
use crate::workloads::containerd::ContainerdAdapter;
use crate::workloads::pod_manager::PodManager;
use fleetos_core::proto::debug::{
    AgentDebugServiceClient, DataChunk, DebugFrame, SessionAck, SessionEnd, SessionStart,
};
use fleetos_core::proto::fleetos::debug_frame;
use fleetos_core::proto::fleetos::session_start;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;

/// Maximum number of concurrent debug sessions per agent.
const MAX_CONCURRENT_SESSIONS: usize = 16;

/// Channel buffer size for outbound debug frames.
const OUTBOUND_BUFFER_SIZE: usize = 256;

/// Per-session stdin routing: session_id → sender for stdin bytes.
pub type StdinRouter = Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>;

/// The debug tunnel: maintains a persistent AgentConnect stream to control
/// and dispatches incoming debug sessions to the appropriate handler.
pub struct DebugTunnel {
    control_client: Arc<ControlPlaneClient>,
    pod_manager: Arc<RwLock<PodManager>>,
    containerd: Arc<ContainerdAdapter>,
}

impl DebugTunnel {
    pub fn new(
        control_client: Arc<ControlPlaneClient>,
        pod_manager: Arc<RwLock<PodManager>>,
        containerd: Arc<ContainerdAdapter>,
    ) -> Self {
        Self {
            control_client,
            pod_manager,
            containerd,
        }
    }

    /// Run the debug tunnel until shutdown. Reconnects with exponential
    /// backoff on failure.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let mut backoff_ms = BASE_RETRY_DELAY_MS;
        tracing::info!("debug tunnel started");

        loop {
            // Check shutdown before each connection attempt.
            if *shutdown.borrow() {
                tracing::info!("debug tunnel shutting down");
                return;
            }

            // Clone BEFORE the select! so the immutable borrow is released
            // before shutdown.changed() takes its mutable borrow.
            let serve_shutdown = shutdown.clone();

            let result = tokio::select! {
                _ = shutdown.changed() => None,
                result = self.connect_and_serve(serve_shutdown) => Some(result),
            };

            match result {
                None => {
                    // Woken by the shutdown channel; loop-top check handles it.
                    continue;
                }
                Some(Ok(())) => {
                    // If connect_and_serve returned because shutdown fired,
                    // skip the "server closed" log and let the loop-top exit.
                    if *shutdown.borrow() {
                        continue;
                    }
                    // Clean disconnect by server; reset backoff.
                    backoff_ms = BASE_RETRY_DELAY_MS;
                    tracing::info!("debug tunnel stream closed by server, reconnecting");
                }
                Some(Err(e)) => {
                    if *shutdown.borrow() {
                        continue;
                    }
                    tracing::warn!(error = %e, "debug tunnel error, reconnecting");
                    tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(MAX_RETRY_DELAY_MS);
                }
            }
        }
    }

    /// Connect to control and serve the debug stream until it closes or errors.
    ///
    /// Takes the shutdown receiver **by value** (a clone from `run`) so
    /// `changed()` can borrow it mutably without conflicting with the caller.
    async fn connect_and_serve(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), AgentError> {
        let channel = self.control_client.get_channel().await?;
        let mut client = AgentDebugServiceClient::new(channel);

        // Outbound channel: handlers write DebugFrames here.
        let (outbound_tx, outbound_rx) = mpsc::channel::<DebugFrame>(OUTBOUND_BUFFER_SIZE);
        let outbound_stream = ReceiverStream::new(outbound_rx);

        // Open the bidi stream.
        let response = client
            .agent_connect(outbound_stream)
            .await
            .map_err(|e| AgentError::Rpc(format!("AgentConnect failed: {}", e)))?;
        let mut inbound = response.into_inner();

        tracing::info!("debug tunnel connected");

        // Session stdin routing table.
        let stdin_router: StdinRouter = Arc::new(Mutex::new(HashMap::new()));
        let mut active_sessions = 0usize;

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        return Ok(());
                    }
                }
                msg = inbound.message() => {
                    match msg {
                        Ok(Some(frame)) => {
                            if let Err(e) = self
                                .dispatch(
                                    frame,
                                    &outbound_tx,
                                    &stdin_router,
                                    &mut active_sessions,
                                )
                                .await
                            {
                                tracing::warn!(error = %e, "debug frame dispatch error");
                            }
                        }
                        Ok(None) => {
                            // Server closed the stream.
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(AgentError::Grpc(e));
                        }
                    }
                }
            }
        }
    }

    /// Dispatch a single DebugFrame to the appropriate handler.
    async fn dispatch(
        &self,
        frame: DebugFrame,
        outbound_tx: &mpsc::Sender<DebugFrame>,
        stdin_router: &StdinRouter,
        active_sessions: &mut usize,
    ) -> Result<(), AgentError> {
        let session_id = frame.session_id.clone();
        let payload = match frame.payload {
            Some(p) => p,
            None => return Ok(()),
        };

        match payload {
            debug_frame::Payload::Start(start) => {
                if *active_sessions >= MAX_CONCURRENT_SESSIONS {
                    let reject =
                        Self::ack_frame(&session_id, false, "too many concurrent sessions");
                    outbound_tx.send(reject).await.map_err(|_| {
                        AgentError::Internal("debug outbound channel closed".into())
                    })?;
                    return Ok(());
                }
                *active_sessions += 1;
                self.handle_session_start(
                    session_id,
                    start,
                    outbound_tx.clone(),
                    stdin_router.clone(),
                )
                .await?;
            }
            debug_frame::Payload::Data(data) => {
                // Route stdin data (channel 0) to the session's stdin channel.
                if data.channel == 0 {
                    let router = stdin_router.lock().await;
                    if let Some(tx) = router.get(&session_id) {
                        let _ = tx.send(data.payload).await;
                    }
                }
            }
            debug_frame::Payload::End(_) => {
                // Session ended by operator. Clean up stdin routing.
                stdin_router.lock().await.remove(&session_id);
                *active_sessions = active_sessions.saturating_sub(1);
            }
            debug_frame::Payload::Ack(_) => {
                // Agent doesn't expect acks from control. Ignore.
            }
        }
        Ok(())
    }

    /// Handle a SessionStart by dispatching to the appropriate handler.
    async fn handle_session_start(
        &self,
        session_id: String,
        start: SessionStart,
        outbound_tx: mpsc::Sender<DebugFrame>,
        stdin_router: StdinRouter,
    ) -> Result<(), AgentError> {
        let pod_id = start.pod_id.clone();
        let kind = match start.kind {
            Some(k) => k,
            None => {
                let reject = Self::ack_frame(&session_id, false, "missing session kind");
                outbound_tx
                    .send(reject)
                    .await
                    .map_err(|_| AgentError::Internal("debug outbound channel closed".into()))?;
                return Ok(());
            }
        };

        // Verify the pod exists.
        let pod_exists = {
            let pm = self.pod_manager.read().await;
            pm.get_pod(&pod_id).is_some()
        };
        if !pod_exists {
            let reject =
                Self::ack_frame(&session_id, false, &format!("pod '{}' not found", pod_id));
            outbound_tx
                .send(reject)
                .await
                .map_err(|_| AgentError::Internal("debug outbound channel closed".into()))?;
            return Ok(());
        }

        match kind {
            session_start::Kind::Exec(exec_req) => {
                exec::handle_exec(
                    session_id,
                    pod_id,
                    exec_req,
                    outbound_tx,
                    stdin_router,
                    self.pod_manager.clone(),
                )
                .await;
            }
            session_start::Kind::Logs(logs_req) => {
                logs::handle_logs(
                    session_id,
                    pod_id,
                    logs_req,
                    outbound_tx,
                    self.pod_manager.clone(),
                    self.containerd.namespace().to_string(),
                )
                .await;
            }
            session_start::Kind::PortForward(pf_req) => {
                port_forward::handle_port_forward(
                    session_id,
                    pod_id,
                    pf_req,
                    outbound_tx,
                    self.pod_manager.clone(),
                )
                .await;
            }
        }
        Ok(())
    }

    // --- Frame construction helpers ---

    pub fn ack_frame(session_id: &str, accepted: bool, reason: &str) -> DebugFrame {
        DebugFrame {
            session_id: session_id.to_string(),
            payload: Some(debug_frame::Payload::Ack(SessionAck {
                accepted,
                reject_reason: reason.to_string(),
            })),
        }
    }

    pub fn data_frame(session_id: &str, channel: u32, payload: Vec<u8>) -> DebugFrame {
        DebugFrame {
            session_id: session_id.to_string(),
            payload: Some(debug_frame::Payload::Data(DataChunk { channel, payload })),
        }
    }

    pub fn end_frame(session_id: &str, error: bool, message: &str) -> DebugFrame {
        DebugFrame {
            session_id: session_id.to_string(),
            payload: Some(debug_frame::Payload::End(SessionEnd {
                error,
                message: message.to_string(),
            })),
        }
    }
}
