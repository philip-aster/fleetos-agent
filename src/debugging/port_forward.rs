// SPDX-License-Identifier: Apache-2.0
//! Port-forward handler (minimal v1).
//!
//! Full port-forwarding requires setting up a TCP proxy between the debug
//! tunnel and the workload's network namespace. This v1 stub acknowledges
//! the session but returns "not implemented" — the infrastructure for
//! bidirectional TCP proxying over the debug tunnel will be added when
//! the router/gateway layer is in place.

use super::{DebugFrame, DebugTunnel};
use crate::workloads::pod_manager::PodManager;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};

/// Handle a port-forward session.
///
/// v1: acknowledges the session but immediately ends it with a
/// "not implemented" message. Full TCP proxying is deferred.
pub async fn handle_port_forward(
    session_id: String,
    pod_id: String,
    req: fleetos_core::proto::debug::PortForwardRequest,
    outbound_tx: mpsc::Sender<DebugFrame>,
    pod_manager: Arc<RwLock<PodManager>>,
) {
    // Verify the pod exists.
    let exists = {
        let pm = pod_manager.read().await;
        pm.get_pod(&pod_id).is_some()
    };

    if !exists {
        let _ = outbound_tx
            .send(DebugTunnel::ack_frame(
                &session_id,
                false,
                &format!("pod '{}' not found", pod_id),
            ))
            .await;
        return;
    }

    // v1: acknowledge but don't implement the proxy.
    let _ = outbound_tx
        .send(DebugTunnel::ack_frame(&session_id, true, ""))
        .await;

    tracing::info!(
        pod_id = %pod_id,
        target_port = req.target_port,
        "port-forward session acknowledged (v1 stub — proxy not yet implemented)"
    );

    let _ = outbound_tx
        .send(DebugTunnel::end_frame(
            &session_id,
            false,
            "port-forward proxy not yet implemented (v1)",
        ))
        .await;
}
