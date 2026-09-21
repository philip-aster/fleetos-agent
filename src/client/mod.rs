// SPDX-License-Identifier: Apache-2.0
//! Control plane client module.
//!
//! Manages the connection to fleetos-control, including TLS channel
//! construction, leader redirect-and-retry logic, and mode switching
//! between pre-SVID (join) and post-SVID (authenticated) states.

pub mod channels;
pub mod retry;
pub mod unary;
pub mod watch;

use crate::identity::svid::SvidState;
use tokio::sync::RwLock;
use tonic::transport::Channel;

/// The main client for communicating with the fleetos-control plane.
///
/// Holds the current target address and the active gRPC channel.
/// Rebuilds the channel when the SVID generation bumps.
pub struct ControlPlaneClient {
    /// The current leader address (e.g., "10.0.1.1:9443").
    current_target: RwLock<String>,
    /// The active gRPC channel. `None` if not yet connected or during rebuild.
    channel: RwLock<Option<Channel>>,
    /// The last known SVID generation, used to detect rotations.
    last_svid_generation: RwLock<u64>,
}

impl ControlPlaneClient {
    pub fn new(initial_target: String) -> Self {
        Self {
            current_target: RwLock::new(initial_target),
            channel: RwLock::new(None),
            last_svid_generation: RwLock::new(0),
        }
    }

    /// Update the target address (e.g., after a leader redirect).
    pub async fn retarget(&self, new_target: String) {
        let mut target = self.current_target.write().await;
        if *target != new_target {
            tracing::info!(old = %*target, new = %new_target, "retargeting control plane client");
            *target = new_target;
            // Invalidate the channel so it's rebuilt on next use
            let mut chan = self.channel.write().await;
            *chan = None;
        }
    }

    /// Check if the SVID has rotated and invalidate the channel if so.
    pub async fn check_svid_rotation(&self, current_state: &SvidState) {
        let mut last_gen = self.last_svid_generation.write().await;
        if current_state.generation > *last_gen {
            tracing::info!(
                old_gen = *last_gen,
                new_gen = current_state.generation,
                "SVID rotated, rebuilding mTLS channel"
            );
            *last_gen = current_state.generation;
            let mut chan = self.channel.write().await;
            *chan = None;
        }
    }
}
