// SPDX-License-Identifier: Apache-2.0
//! Control plane client module.
//!
//! Manages the connection to fleetos-control, including TLS channel
//! construction, leader redirect-and-retry logic, and mode switching
//! between pre-SVID (join) and post-SVID (authenticated) states.
//!
//! Phase 8.4.5: `trust_bundle_pem` is `Arc<RwLock<String>>` so the
//! periodic GetTrustBundle refresh task can update it in place.
//! `update_trust_bundle` invalidates the cached channel, forcing
//! `get_channel` to rebuild with the new bundle on the next call.
//!
//! Lock ordering (deadlock prevention):
//!   `channel` is ALWAYS acquired before `trust_bundle_pem`.
//!   `get_channel` holds `channel.write()` then reads `trust_bundle_pem`.
//!   `update_trust_bundle` acquires `channel.write()` then `trust_bundle_pem.write()`.
//!   Same order everywhere — no deadlock.
pub mod channels;
pub mod retry;
pub mod unary;
pub mod watch;
use crate::client::channels::build_mtls_channel;
use crate::error::AgentError;
use crate::identity::keystore::TpmSealedStore;
use crate::identity::svid::SvidState;
use crate::storage::Storage;
use fleetos_core::proto::fleetos::{
    pod_event_service_client::PodEventServiceClient,
    workload_status_service_client::WorkloadStatusServiceClient,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Channel;
/// The main client for communicating with the fleetos-control plane.
///
/// Holds the current target address and the active gRPC channel.
/// Rebuilds the channel when the SVID generation bumps or the trust
/// bundle is refreshed.
pub struct ControlPlaneClient {
    /// The current leader address (e.g., "10.0.1.1:9443").
    current_target: RwLock<String>,
    /// The active gRPC channel. `None` if not yet connected or during rebuild.
    channel: RwLock<Option<Channel>>,
    /// The last known SVID generation, used to detect rotations.
    last_svid_generation: RwLock<u64>,
    /// Dependencies required to rebuild the mTLS channel.
    storage: Arc<Storage>,
    keystore: Arc<TpmSealedStore>,
    /// Trust bundle PEM. `RwLock` so the periodic refresh task (8.4.5)
    /// can update it without replacing the entire client.
    trust_bundle_pem: Arc<RwLock<String>>,
    svid_state: Arc<RwLock<SvidState>>,
}
impl ControlPlaneClient {
    pub fn new(
        initial_target: String,
        storage: Arc<Storage>,
        keystore: Arc<TpmSealedStore>,
        trust_bundle_pem: Arc<RwLock<String>>,
        svid_state: Arc<RwLock<SvidState>>,
    ) -> Self {
        Self {
            current_target: RwLock::new(initial_target),
            channel: RwLock::new(None),
            last_svid_generation: RwLock::new(0),
            storage,
            keystore,
            trust_bundle_pem,
            svid_state,
        }
    }
    /// Get a valid channel to the control plane.
    /// Rebuilds if retargeted, if SVID rotated, or if trust bundle was updated.
    pub async fn get_channel(&self) -> Result<Channel, AgentError> {
        let mut channel_guard = self.channel.write().await;
        // Check SVID rotation
        let svid_state_guard = self.svid_state.read().await;
        let mut last_gen = self.last_svid_generation.write().await;
        if svid_state_guard.generation > *last_gen {
            tracing::info!(
                old_gen = *last_gen,
                new_gen = svid_state_guard.generation,
                "SVID rotated, rebuilding mTLS channel"
            );
            *last_gen = svid_state_guard.generation;
            *channel_guard = None;
        }
        if let Some(chan) = channel_guard.clone() {
            return Ok(chan);
        }
        let target = self.current_target.read().await.clone();
        let cert_chain_der = svid_state_guard.cert_chain_der.clone();
        drop(svid_state_guard); // Release lock before blocking on TPM or async build
        let private_key_der = self
            .keystore
            .load_svid_private_key(&self.storage)?
            .ok_or_else(|| AgentError::Identity("SVID private key not found in keystore".into()))?;
        // Read the current trust bundle (may have been refreshed by 8.4.5 task).
        let trust_bundle = self.trust_bundle_pem.read().await;
        let new_channel =
            build_mtls_channel(&target, &trust_bundle, &cert_chain_der, &private_key_der).await?;
        *channel_guard = Some(new_channel.clone());
        Ok(new_channel)
    }
    /// Update the trust bundle and invalidate the current channel (8.4.5).
    ///
    /// The next `get_channel` call will rebuild the mTLS channel with the
    /// new bundle. Lock ordering: `channel` → `trust_bundle_pem` (matches
    /// `get_channel` to prevent deadlock).
    pub async fn update_trust_bundle(&self, new_pem: String) {
        let mut channel_guard = self.channel.write().await;
        let mut bundle = self.trust_bundle_pem.write().await;
        if *bundle != new_pem {
            tracing::info!("trust bundle updated, invalidating channel for rebuild");
            *bundle = new_pem;
            *channel_guard = None;
        }
    }
    /// Get the current target address.
    pub async fn current_target(&self) -> String {
        self.current_target.read().await.clone()
    }
    /// Update the target address (e.g., after a leader redirect).
    pub async fn retarget(&self, new_target: String) {
        let mut target = self.current_target.write().await;
        if *target != new_target {
            tracing::info!(old = %*target, new = %new_target, "retargeting control plane client");
            *target = new_target;
            let mut chan = self.channel.write().await;
            *chan = None;
        }
    }
    /// Create a typed client for WorkloadStatus reporting.
    pub async fn workload_status_client(
        &self,
    ) -> Result<WorkloadStatusServiceClient<Channel>, AgentError> {
        Ok(WorkloadStatusServiceClient::new(self.get_channel().await?))
    }
    /// Create a typed client for PodEvent reporting.
    pub async fn pod_event_client(&self) -> Result<PodEventServiceClient<Channel>, AgentError> {
        Ok(PodEventServiceClient::new(self.get_channel().await?))
    }
}
