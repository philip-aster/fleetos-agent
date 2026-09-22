// SPDX-License-Identifier: Apache-2.0
//! Secret delivery: proto → core conversion, unseal, replay check.
//!
//! The delivery pipeline is:
//!   1. Convert proto SealedSecret → core SealedSecret
//!   2. Check sequence via SecretSequenceTracker (replay protection)
//!   3. Unseal with the agent's X25519 private key
//!   4. Hand plaintext to the workload (TODO: Batch 10)
//!
//! Ruling G: the private key used for unseal is TPM-sealed in storage.
//! It is loaded via the keystore (Batch 2) and never touches disk in plaintext.

use crate::error::AgentError;
use crate::identity::sequences;
use crate::storage::Storage;
use fleetos_core::crypto::{SealedSecret as CoreSealedSecret, SecretSequence};
use fleetos_core::proto::secret::SealedSecret as ProtoSealedSecret;
use zeroize::Zeroizing;

/// Convert a proto SealedSecret to the core SealedSecret type.
///
/// This is a pure conversion — no I/O, no side effects.
/// Returns an error if the proto fields are malformed.
pub fn proto_to_core(proto: &ProtoSealedSecret) -> Result<CoreSealedSecret, AgentError> {
    // ephemeral_pubkey must be exactly 32 bytes (X25519).
    let ephemeral_pubkey: [u8; 32] =
        proto.ephemeral_pubkey.as_slice().try_into().map_err(|_| {
            AgentError::Secret(format!(
                "ephemeral_pubkey must be 32 bytes, got {}",
                proto.ephemeral_pubkey.len()
            ))
        })?;

    Ok(CoreSealedSecret {
        sealed_for_svid_version: proto.sealed_for_svid_version,
        sequence: SecretSequence(proto.sequence),
        ephemeral_pubkey,
        ciphertext: proto.ciphertext.clone(),
    })
}

/// Deliver a secret: convert, check sequence, unseal.
///
/// Returns the plaintext secret bytes (zeroized on drop).
/// The caller is responsible for handing the plaintext to the workload.
///
/// TODO(Batch 10): Wire the workload delivery mechanism. For now, this
/// returns the plaintext for the caller to handle.
pub fn deliver_secret(
    storage: &Storage,
    proto_secret: &ProtoSealedSecret,
    private_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    let target = &proto_secret.target_spiffe_id;
    let svid_version = proto_secret.sealed_for_svid_version;
    let sequence = proto_secret.sequence;

    // 1. Replay check: strictly-newer-or-reject per (target, svid_version).
    let accepted = sequences::check_and_record(storage, target, svid_version, sequence)?;
    if !accepted {
        tracing::warn!(
            target = %target,
            svid_version = svid_version,
            sequence = sequence,
            "secret rejected: replay or stale sequence"
        );
        return Err(AgentError::Secret(format!(
            "secret rejected: sequence {} is not newer for target {} (svid_version={})",
            sequence, target, svid_version
        )));
    }

    // 2. Convert proto → core.
    let core_secret = proto_to_core(proto_secret)?;

    // 3. Unseal with the agent's private key.
    let plaintext = fleetos_core::crypto::unseal(private_key, &core_secret)
        .map_err(|e| AgentError::Secret(format!("unseal failed: {}", e)))?;

    tracing::debug!(
        target = %target,
        svid_version = svid_version,
        sequence = sequence,
        "secret delivered"
    );

    Ok(plaintext)
}
