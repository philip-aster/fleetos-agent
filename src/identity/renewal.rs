// SPDX-License-Identifier: Apache-2.0
//! Node SVID renewal loop (Phase 8.4.2).
//!
//! Renews the node SVID before expiry by generating a fresh keypair,
//! building a CSR with the node's SPIFFE ID, submitting it via `SubmitCsr`,
//! and atomically storing the new cert + sealed private key.
//!
//! Timing: renews at `refresh_fraction` of the SVID TTL (default 75% of
//! 1 hour = 45 minutes). The loop is leader-redirect-aware: `submit_csr`
//! handles UNAVAILABLE + `leader-dc-address` metadata via the standard
//! redirect-and-retry helper.
//!
//! Ruling G: the new private key is TPM-sealed (or software-sealed in
//! insecure mode) before being persisted. The old key is overwritten in
//! storage — fjall's `insert` is an upsert on the same key label.
//!
//! Failure semantics: a failed renewal is non-fatal. The existing SVID
//! remains valid until its TTL expires. The loop logs the error and retries
//! on the next tick. Only if renewals fail for the entire remaining TTL
//! window does the node lose its identity.
use crate::client::ControlPlaneClient;
use crate::client::unary;
use crate::error::AgentError;
use crate::identity::keystore::{SensitiveStore, TpmSealedStore};
use crate::identity::svid::{self, SvidState};
use crate::storage::Storage;
use fleetos_core::spiffe::SpiffeId;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
/// Storage key for the node SVID private key.
/// Must match the key used in `join/secure.rs` and `join/insecure.rs`.
const KEY_SVID_PRIVATE_KEY: &[u8] = b"svid_private_key";
/// Configuration for the renewal loop, derived from `[svid]` in agent.toml.
#[derive(Debug, Clone)]
pub struct RenewalConfig {
    /// Node SVID TTL in seconds (from `[svid] ttl_secs`).
    pub ttl_secs: u64,
    /// Fraction of TTL at which renewal is triggered (from `[svid] refresh_fraction`).
    /// Must be in (0.0, 1.0). Validated by `AgentConfig::validate`.
    pub refresh_fraction: f64,
}
impl RenewalConfig {
    /// Compute the renewal interval: `ttl_secs * refresh_fraction`.
    ///
    /// For the default config (3600s TTL, 0.75 fraction) this is 2700s = 45 min.
    /// A floor of 60 seconds prevents pathological renewal storms from
    /// misconfiguration.
    pub fn renewal_interval(&self) -> Duration {
        let interval_secs = (self.ttl_secs as f64 * self.refresh_fraction) as u64;
        Duration::from_secs(interval_secs.max(60))
    }
}
/// The node SVID renewal loop.
///
/// Runs as a background tokio task. On each tick:
/// 1. Generates a fresh rcgen keypair.
/// 2. Builds a CSR carrying ONLY the node SPIFFE ID (no custom extensions —
///    the CA stamps those at signing time per the `build_csr` contract).
/// 3. Submits via `SubmitCsr` (redirect-and-retry handled by `client::unary`).
/// 4. Seals the new private key via the keystore (TPM or software, Ruling G).
/// 5. Persists the new SVID state, bumping the generation counter.
/// 6. Updates the in-memory `SvidState` so `ControlPlaneClient::get_channel`
///    detects the rotation and rebuilds the mTLS channel.
pub struct SvidRenewalLoop {
    control_client: Arc<ControlPlaneClient>,
    keystore: Arc<TpmSealedStore>,
    storage: Arc<Storage>,
    svid_state: Arc<RwLock<SvidState>>,
    node_spiffe_id: SpiffeId,
    config: RenewalConfig,
}
impl SvidRenewalLoop {
    pub fn new(
        control_client: Arc<ControlPlaneClient>,
        keystore: Arc<TpmSealedStore>,
        storage: Arc<Storage>,
        svid_state: Arc<RwLock<SvidState>>,
        node_spiffe_id: SpiffeId,
        config: RenewalConfig,
    ) -> Self {
        Self {
            control_client,
            keystore,
            storage,
            svid_state,
            node_spiffe_id,
            config,
        }
    }
    /// Run the renewal loop until the shutdown signal fires.
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) {
        let interval = self.config.renewal_interval();
        tracing::info!(
            interval_secs = interval.as_secs(),
            ttl_secs = self.config.ttl_secs,
            refresh_fraction = self.config.refresh_fraction,
            "node SVID renewal loop started"
        );
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("SVID renewal loop shutting down");
                        return;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(e) = self.renew().await {
                        // Renewal failure is non-fatal: the existing SVID is
                        // still valid until its TTL expires. Log loudly and
                        // retry on the next tick.
                        tracing::error!(
                            error = %e,
                            "node SVID renewal failed; will retry next tick"
                        );
                    }
                }
            }
        }
    }
    /// Perform a single renewal cycle.
    pub async fn renew(&self) -> Result<(), AgentError> {
        tracing::info!("beginning node SVID renewal");
        // 1. Generate a fresh keypair.
        let keypair = rcgen::KeyPair::generate()
            .map_err(|e| AgentError::Identity(format!("rcgen keygen failed: {}", e)))?;
        let private_key_der = keypair.serialize_der();
        // 2. Build a CSR with the node SPIFFE ID.
        //    Contract: the CSR carries ONLY the SPIFFE URI SAN + standard
        //    extensions. Role/ordinal/degraded are stamped by the CA at
        //    signing time — never embedded in the CSR (build_csr contract).
        let csr = fleetos_core::spiffe::ca::build_csr(&self.node_spiffe_id, &keypair)
            .map_err(|e| AgentError::Identity(format!("CSR build failed: {}", e)))?;
        // 3. Submit the CSR via the standard redirect-and-retry path.
        let response = unary::submit_csr(&self.control_client, csr.der.clone()).await?;
        // 4. Seal the new private key (TPM or software, per Ruling G).
        //    This overwrites the previous sealed blob at the same key label.
        self.keystore
            .store_sealed(&self.storage, KEY_SVID_PRIVATE_KEY, &private_key_der)?;
        // 5. Persist the new SVID state, bumping the generation counter.
        let current_gen = {
            let state = self.svid_state.read().await;
            state.generation
        };
        let new_state = svid::store(
            &self.storage,
            &[response.cert_chain_der],
            response.svid_version,
            current_gen,
        )?;
        // 6. Update the in-memory state so the mTLS channel is rebuilt.
        {
            let mut state = self.svid_state.write().await;
            *state = new_state;
        }
        tracing::info!(
            svid_version = response.svid_version,
            generation = current_gen + 1,
            "node SVID renewed successfully"
        );
        Ok(())
    }
}
