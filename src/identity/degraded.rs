// SPDX-License-Identifier: Apache-2.0
//! DelegatedSigningKey lifecycle (degraded-mode SVID renewal).
//!
//! When the control plane is unreachable, the agent can renew workload SVIDs
//! locally using a delegated signing key. This module manages the key's
//! lifecycle:
//!
//!   1. Acquire via `DelegationService.RequestDelegatedKey` (leader-bound)
//!   2. Track the 4-hour TTL
//!   3. Refresh at 75% elapsed while control is reachable
//!   4. Renew workload SVIDs locally via `sign_svid_delegated` when unreachable
//!
//! Ruling G: the delegated signing key is TPM-sealed in storage. It is
//! never stored in plaintext. The keystore (Batch 2) handles sealing/unsealing.
//!
//! Structural backstop: the intermediate cert carries NameConstraints
//! restricting URI SANs to the trust domain. Within the trust domain,
//! target-SVID/ordinal checks are application-level (enforced by
//! `sign_svid_delegated`).
use crate::error::AgentError;
use fleetos_core::spiffe::DelegatedSigningKey;
use std::time::Duration;

/// Default TTL for delegated signing keys: 4 hours.
pub const DEFAULT_DELEGATED_KEY_TTL_SECS: u64 = 14400;

/// Fraction of TTL at which refresh is triggered: 75%.
pub const REFRESH_FRACTION: f64 = 0.75;

/// Tracks a delegated signing key and its lifecycle.
pub struct DelegatedKeyManager {
    /// The current delegated key, if acquired.
    key: Option<DelegatedSigningKey>,
    /// The delegation ID (opaque, from control).
    delegation_id: Option<Vec<u8>>,
}

impl DelegatedKeyManager {
    pub fn new() -> Self {
        Self {
            key: None,
            delegation_id: None,
        }
    }

    /// Returns true if a delegated key is currently held and not expired.
    pub fn has_valid_key(&self, now_unix: u64) -> bool {
        match &self.key {
            Some(key) => now_unix < key.expires_at_unix,
            None => false,
        }
    }

    /// Returns true if the key should be refreshed (75% of TTL elapsed).
    ///
    /// Only called while control is reachable. If control is unreachable,
    /// the agent uses the existing key for local renewal until it expires.
    pub fn should_refresh(&self, now_unix: u64) -> bool {
        match &self.key {
            Some(key) => {
                let ttl = key.expires_at_unix.saturating_sub(key.issued_at_unix);
                let refresh_at = key.issued_at_unix + (ttl as f64 * REFRESH_FRACTION) as u64;
                now_unix >= refresh_at
            }
            None => false,
        }
    }

    /// Returns the remaining TTL in seconds, or 0 if expired/absent.
    pub fn remaining_ttl_secs(&self, now_unix: u64) -> u64 {
        match &self.key {
            Some(key) => key.expires_at_unix.saturating_sub(now_unix),
            None => 0,
        }
    }

    /// Install a newly acquired or refreshed delegated key.
    pub fn install_key(&mut self, key: DelegatedSigningKey, delegation_id: Vec<u8>) {
        tracing::info!(
            target_svid = %key.target_svid_id,
            expires_at = key.expires_at_unix,
            "delegated signing key installed"
        );
        self.key = Some(key);
        self.delegation_id = Some(delegation_id);
    }

    /// Get the current delegated key for local SVID renewal.
    ///
    /// Returns None if no key is held or it has expired.
    pub fn get_key(&self, now_unix: u64) -> Option<&DelegatedSigningKey> {
        match &self.key {
            Some(key) if now_unix < key.expires_at_unix => Some(key),
            _ => None,
        }
    }

    /// Renew a workload SVID locally using the delegated signing key.
    ///
    /// This is the degraded-mode path: control is unreachable, so the agent
    /// signs the new SVID itself using the delegated key. The structural
    /// backstop (NameConstraints on the intermediate cert) restricts the
    /// signed SVID to the trust domain.
    ///
    /// Returns the DER-encoded certificate chain for the renewed SVID.
    pub fn renew_svid_locally(
        &self,
        csr_der: &[u8],
        validity: Duration,
        now_unix: u64,
    ) -> Result<Vec<u8>, AgentError> {
        let key = self.get_key(now_unix).ok_or_else(|| {
            AgentError::Identity("no valid delegated key for local renewal".into())
        })?;

        let cert_der =
            fleetos_core::spiffe::ca::sign_svid_delegated(key, csr_der, validity, now_unix)
                .map_err(|e| AgentError::Identity(format!("local SVID renewal failed: {}", e)))?;

        tracing::info!(
            target_svid = %key.target_svid_id,
            validity_secs = validity.as_secs(),
            "workload SVID renewed locally (degraded mode)"
        );

        Ok(cert_der)
    }

    /// Clear the delegated key (e.g., on revocation or shutdown).
    pub fn clear(&mut self) {
        self.key = None;
        self.delegation_id = None;
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
