// SPDX-License-Identifier: Apache-2.0
//! DelegatedSigningKey lifecycle (degraded-mode SVID renewal).
//!
//! When the control plane is unreachable, the agent can renew workload SVIDs
//! locally using a delegated signing key. This module manages the keys'
//! lifecycle:
//!
//!   1. Acquire via `DelegationService.RequestDelegatedKey` (leader-bound)
//!   2. Track the 4-hour TTL
//!   3. Refresh at 75% elapsed while control is reachable
//!   4. Renew workload SVIDs locally via `sign_svid_delegated` when unreachable
//!
//! A node hosts multiple workloads, each with its own delegated renewal key
//! scoped to a specific `target_svid_id`. The manager is therefore map-based,
//! keyed by the target workload SPIFFE ID.
//!
//! Ruling G: the delegated signing key is TPM-sealed in storage. It is never
//! stored in plaintext. The keystore (Batch 2) handles sealing/unsealing.
//!
//! Structural backstop: the intermediate cert carries NameConstraints
//! restricting URI SANs to the trust domain. Within the trust domain,
//! target-SVID/ordinal checks are application-level (enforced by
//! `sign_svid_delegated`).
use crate::error::AgentError;
use fleetos_core::spiffe::{DelegatedSigningKey, SpiffeId};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Default TTL for delegated signing keys: 4 hours.
pub const DEFAULT_DELEGATED_KEY_TTL_SECS: u64 = 14400;
/// Fraction of TTL at which refresh is triggered: 75%.
pub const REFRESH_FRACTION: f64 = 0.75;

/// A single delegated key entry with its delegation id.
struct DelegatedKeyEntry {
    key: DelegatedSigningKey,
    delegation_id: Vec<u8>,
}

/// Map-based manager holding delegated signing keys, one per target workload
/// SPIFFE ID.
///
/// A node hosts multiple workloads, each with its own delegated renewal key,
/// so a single-slot store cannot represent the node's full renewal capability.
pub struct DelegatedKeyManager {
    /// Target workload SPIFFE ID -> delegated key entry.
    keys: HashMap<SpiffeId, DelegatedKeyEntry>,
}

impl DelegatedKeyManager {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Install or replace the delegated key for its target workload.
    ///
    /// The map key is derived from `key.target_svid_id`, so the key is always
    /// filed under the workload it is scoped to renew.
    pub fn install_key(&mut self, key: DelegatedSigningKey, delegation_id: Vec<u8>) {
        let target = key.target_svid_id.clone();
        tracing::info!(
            target_svid = %target,
            expires_at = key.expires_at_unix,
            "delegated signing key installed"
        );
        self.keys
            .insert(target, DelegatedKeyEntry { key, delegation_id });
    }

    /// Returns all delegation IDs currently held. Used for revocation handling
    /// (matching against `revoked_delegation_ids` streamed via WatchSag).
    pub fn delegation_ids(&self) -> Vec<Vec<u8>> {
        self.keys
            .values()
            .map(|e| e.delegation_id.clone())
            .collect()
    }

    /// Returns true if a valid (unexpired) delegated key is held for the target.
    pub fn has_valid_key(&self, target_svid_id: &SpiffeId, now_unix: u64) -> bool {
        self.keys
            .get(target_svid_id)
            .map_or(false, |e| now_unix < e.key.expires_at_unix)
    }

    /// Returns true if the key for the target should be refreshed
    /// (75% of TTL elapsed).
    pub fn should_refresh(&self, target_svid_id: &SpiffeId, now_unix: u64) -> bool {
        match self.keys.get(target_svid_id) {
            Some(e) => {
                let ttl = e.key.expires_at_unix.saturating_sub(e.key.issued_at_unix);
                let refresh_at = e.key.issued_at_unix + (ttl as f64 * REFRESH_FRACTION) as u64;
                now_unix >= refresh_at
            }
            None => false,
        }
    }

    /// Remaining TTL in seconds for the target's key, or 0 if absent/expired.
    pub fn remaining_ttl_secs(&self, target_svid_id: &SpiffeId, now_unix: u64) -> u64 {
        self.keys
            .get(target_svid_id)
            .map_or(0, |e| e.key.expires_at_unix.saturating_sub(now_unix))
    }

    /// Get the delegated key for the target if valid (unexpired).
    pub fn get_key(
        &self,
        target_svid_id: &SpiffeId,
        now_unix: u64,
    ) -> Option<&DelegatedSigningKey> {
        self.keys
            .get(target_svid_id)
            .filter(|e| now_unix < e.key.expires_at_unix)
            .map(|e| &e.key)
    }

    /// All target SPIFFE IDs whose keys should be refreshed.
    pub fn keys_needing_refresh(&self, now_unix: u64) -> Vec<SpiffeId> {
        self.keys
            .keys()
            .filter(|id| self.should_refresh(id, now_unix))
            .cloned()
            .collect()
    }

    /// All currently-installed target SPIFFE IDs.
    pub fn targets(&self) -> Vec<SpiffeId> {
        self.keys.keys().cloned().collect()
    }

    /// Remove a delegated key (revocation/expiry).
    pub fn remove(&mut self, target_svid_id: &SpiffeId) {
        self.keys.remove(target_svid_id);
    }

    /// Remove all expired keys.
    pub fn prune_expired(&mut self, now_unix: u64) {
        self.keys.retain(|_, e| now_unix < e.key.expires_at_unix);
    }

    /// Clear all keys.
    pub fn clear(&mut self) {
        self.keys.clear();
    }

    /// Renew a workload SVID locally using the delegated key for the target.
    ///
    /// This is the degraded-mode path: control is unreachable, so the agent
    /// signs the new SVID itself using the delegated key. The structural
    /// backstop (NameConstraints on the intermediate cert) restricts the
    /// signed SVID to the trust domain.
    ///
    /// Returns the DER-encoded leaf certificate for the renewed SVID.
    pub fn renew_svid_locally(
        &self,
        target_svid_id: &SpiffeId,
        csr_der: &[u8],
        validity: Duration,
        now_unix: u64,
    ) -> Result<Vec<u8>, AgentError> {
        let key = self.get_key(target_svid_id, now_unix).ok_or_else(|| {
            AgentError::Identity(format!(
                "no valid delegated key for target {}",
                target_svid_id
            ))
        })?;
        let cert_der =
            fleetos_core::spiffe::ca::sign_svid_delegated(key, csr_der, validity, now_unix)
                .map_err(|e| AgentError::Identity(format!("local SVID renewal failed: {}", e)))?;
        tracing::info!(
            target_svid = %target_svid_id,
            validity_secs = validity.as_secs(),
            "workload SVID renewed locally (degraded mode)"
        );
        Ok(cert_der)
    }
}

impl Default for DelegatedKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Current unix timestamp in seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Request a delegated key for a target workload and install it into the manager.
///
/// Called when a workload is booted (so its SVID can be generated at config
/// push) and by the refresh loop for keys nearing expiry.
pub async fn request_and_install(
    client: &crate::client::ControlPlaneClient,
    manager: &Arc<RwLock<DelegatedKeyManager>>,
    node_svid_id: &SpiffeId,
    target_svid_id: &SpiffeId,
    target_ordinal: Option<u32>,
    ttl_secs: u64,
) -> Result<(), AgentError> {
    let request = fleetos_core::proto::fleetos::DelegatedKeyRequest {
        node_svid: node_svid_id.to_string(),
        target_spiffe_id: target_svid_id.to_string(),
        target_ordinal,
        requested_ttl_secs: ttl_secs,
    };
    let response = crate::client::unary::request_delegated_key(client, request).await?;
    let key = parse_key_material(&response.key_material)?;
    let mut mgr = manager.write().unwrap();
    mgr.install_key(key, response.delegation_id);
    Ok(())
}

/// Background refresh loop for delegated keys (75% TTL).
///
/// Periodically prunes expired keys and re-requests any key whose TTL is
/// >= 75% elapsed. If control is unreachable the request fails and the
/// existing key continues to be used until expiry (retry next tick).
pub async fn run_delegation_refresh_loop(
    client: Arc<crate::client::ControlPlaneClient>,
    manager: Arc<RwLock<DelegatedKeyManager>>,
    node_svid_id: SpiffeId,
    ttl_secs: u64,
    check_interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut ticker = tokio::time::interval(check_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    tracing::info!("delegation refresh loop shutting down");
                    return;
                }
            }
            _ = ticker.tick() => {
                let now = now_unix();
                // Prune expired keys and collect targets needing refresh.
                // Lock is held only for the brief read/collect, never across
                // the async request below.
                let needs_refresh: Vec<(SpiffeId, Option<u32>)> = {
                    let mut mgr = manager.write().unwrap();
                    mgr.prune_expired(now);
                    mgr.targets()
                        .into_iter()
                        .filter_map(|id| {
                            if mgr.should_refresh(&id, now) {
                                let ordinal = mgr.get_key(&id, now).and_then(|k| k.target_ordinal);
                                Some((id, ordinal))
                            } else {
                                None
                            }
                        })
                        .collect()
                };
                for (target, ordinal) in needs_refresh {
                    match request_and_install(
                        &client, &manager, &node_svid_id, &target, ordinal, ttl_secs,
                    )
                    .await
                    {
                        Ok(()) => tracing::info!(target = %target, "delegated key refreshed"),
                        Err(e) => tracing::warn!(
                            target = %target,
                            error = %e,
                            "delegated key refresh failed; existing key used until expiry"
                        ),
                    }
                }
            }
        }
    }
}

/// Wire-format mirror of `DelegatedSigningKey` for postcard deserialization.
///
/// `DelegatedSigningKey` in `fleetos-core` contains a `Zeroizing<Vec<u8>>` which
/// does not implement `serde::Deserialize` (the `zeroize` crate's `serde` feature
/// is not enabled in core). We deserialize into plain `Vec<u8>` and wrap it in
/// `Zeroizing` manually.
///
/// Field order MUST exactly match the canonical order documented in state.proto
/// and used by fleetos-control's serialization.
#[derive(serde::Deserialize)]
struct DelegatedSigningKeyWire {
    node_id: fleetos_core::spiffe::SpiffeId,
    target_svid_id: fleetos_core::spiffe::SpiffeId,
    target_ordinal: Option<u32>,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signing_key: Vec<u8>,
    intermediate_cert_der: Vec<u8>,
    target_role: Option<fleetos_core::spiffe::WorkloadRole>,
}

/// Parse the `DelegatedKeyResponse.key_material` into a `DelegatedSigningKey`.
///
/// The key_material is postcard-encoded. This is a pure deserialization.
pub fn parse_key_material(key_material: &[u8]) -> Result<DelegatedSigningKey, AgentError> {
    let wire: DelegatedSigningKeyWire = postcard::from_bytes(key_material)
        .map_err(|e| AgentError::Identity(format!("failed to parse key_material: {}", e)))?;
    Ok(DelegatedSigningKey {
        node_id: wire.node_id,
        target_svid_id: wire.target_svid_id,
        target_ordinal: wire.target_ordinal,
        issued_at_unix: wire.issued_at_unix,
        expires_at_unix: wire.expires_at_unix,
        signing_key: zeroize::Zeroizing::new(wire.signing_key),
        intermediate_cert_der: wire.intermediate_cert_der,
        target_role: wire.target_role,
    })
}
