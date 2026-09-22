// SPDX-License-Identifier: Apache-2.0
//! VSOCK quote verification — fail-closed.
//!
//! Dispatches by `quote_type`:
//!   - `0xFF` (Dev software): reject in production builds.
//!   - `3` (Host-Measured): verify CID matches a launched VM + boot-artifact hash.
//!   - `1/2` (SEV-SNP/TDX): gate exists, fail-closed (not yet implemented).
//!   - `0` (TPM2): gate exists, fail-closed (not yet implemented).
//!
//! Nonce binding is enforced for all quote types.
//! `protocol_version != 1` is rejected at the handshake level (mod.rs).

use fleetos_core::nonce::Nonce;
use fleetos_core::vsock_proto::*;

use super::measure::BootMeasurement;
use crate::error::AgentError;

/// Verifier for VSOCK guest attestation quotes.
///
/// This is the agent-side counterpart to the guest-init's quote generation.
/// It does NOT implement the TPM `QuoteVerifier` trait (those types are
/// TPM-specific); instead it provides VSOCK-specific verification logic
/// that handles the different quote types defined in `vsock_proto`.
pub struct VsockQuoteVerifier {
    /// Whether to accept dev software quotes. MUST be false in production.
    #[cfg(feature = "production")]
    _production_marker: (),
}

impl VsockQuoteVerifier {
    pub fn new() -> Self {
        Self {
            #[cfg(feature = "production")]
            _production_marker: (),
        }
    }

    /// Verify a guest's attestation proof.
    ///
    /// Fail-closed: any unrecognized quote type, missing measurement, or
    /// verification failure results in rejection.
    pub fn verify(
        &self,
        proof: &VsockAttestationProof,
        nonce: &Nonce,
        peer_cid: u32,
        measurement: Option<&BootMeasurement>,
    ) -> Result<VerifiedGuest, AgentError> {
        match proof.quote_type {
            QUOTE_TYPE_DEV_SOFTWARE => self.verify_dev_software(proof, nonce),
            QUOTE_TYPE_HOST_MEASURED => {
                self.verify_host_measured(proof, nonce, peer_cid, measurement)
            }
            QUOTE_TYPE_TPM2 => Err(AgentError::Attestation(
                "TPM2 guest attestation not yet implemented (fail-closed)".into(),
            )),
            QUOTE_TYPE_SEV_SNP => Err(AgentError::Attestation(
                "SEV-SNP guest attestation not yet implemented (fail-closed)".into(),
            )),
            QUOTE_TYPE_TDX => Err(AgentError::Attestation(
                "TDX guest attestation not yet implemented (fail-closed)".into(),
            )),
            unknown => Err(AgentError::Attestation(format!(
                "unknown quote_type {} (fail-closed)",
                unknown
            ))),
        }
    }

    /// Dev software quote: reject in production, accept in dev builds.
    fn verify_dev_software(
        &self,
        proof: &VsockAttestationProof,
        nonce: &Nonce,
    ) -> Result<VerifiedGuest, AgentError> {
        // In production builds, dev software quotes are ALWAYS rejected.
        #[cfg(feature = "production")]
        {
            let _ = (proof, nonce);
            return Err(AgentError::Attestation(
                "QUOTE_TYPE_DEV_SOFTWARE rejected in production build (fail-closed)".into(),
            ));
        }

        // In non-production builds, verify the nonce binding and accept.
        #[cfg(not(feature = "production"))]
        {
            self.verify_nonce_binding(proof, nonce)?;
            tracing::warn!("accepting DEV software quote (INSECURE — non-production build only)");
            Ok(VerifiedGuest {
                guest_x25519_pubkey: proof.guest_x25519_pubkey,
            })
        }
    }

    /// Host-measured quote: verify CID matches a launched VM and the
    /// boot-artifact hash matches the pre-launch measurement.
    ///
    /// This is the primary non-CC attestation path. The security model is:
    ///   1. The agent measured kernel + rootfs + guest-init before launch.
    ///   2. The guest's quote includes that measurement.
    ///   3. The agent verifies the CID matches the VM it launched.
    ///   4. The agent verifies the measurement matches.
    fn verify_host_measured(
        &self,
        proof: &VsockAttestationProof,
        nonce: &Nonce,
        peer_cid: u32,
        measurement: Option<&BootMeasurement>,
    ) -> Result<VerifiedGuest, AgentError> {
        // Nonce binding is mandatory.
        self.verify_nonce_binding(proof, nonce)?;

        // The measurement must exist (the agent must have launched this VM).
        let measurement = measurement.ok_or_else(|| {
            AgentError::Attestation(format!(
                "no boot measurement registered for CID {} (fail-closed)",
                peer_cid
            ))
        })?;

        // The guest's quote must include the expected measurement hash.
        // The raw_quote contains the measurement hash (32 bytes BLAKE3).
        if proof.raw_quote.len() < 32 {
            return Err(AgentError::Attestation(
                "host-measured quote too short (fail-closed)".into(),
            ));
        }

        let quote_hash: [u8; 32] = proof.raw_quote[..32]
            .try_into()
            .map_err(|_| AgentError::Attestation("invalid quote hash length".into()))?;

        if quote_hash != measurement.combined_hash {
            return Err(AgentError::Attestation(format!(
                "boot measurement mismatch for CID {}: expected {:?}, got {:?} (fail-closed)",
                peer_cid, measurement.combined_hash, quote_hash
            )));
        }

        tracing::info!(peer_cid, "host-measured attestation verified");

        Ok(VerifiedGuest {
            guest_x25519_pubkey: proof.guest_x25519_pubkey,
        })
    }

    /// Verify that the quote is bound to the challenge nonce.
    ///
    /// The nonce must appear in the raw_quote. The exact binding mechanism
    /// depends on the quote type; for host-measured quotes, the nonce is
    /// included in the measurement input. For TPM/SEV/TDX quotes, the
    /// nonce is embedded in the quote structure by the hardware.
    fn verify_nonce_binding(
        &self,
        proof: &VsockAttestationProof,
        nonce: &Nonce,
    ) -> Result<(), AgentError> {
        let nonce_bytes = nonce.as_bytes();

        // For host-measured and dev quotes, the nonce must be present in raw_quote.
        // For hardware quotes (TPM/SEV/TDX), the nonce binding is verified by
        // the hardware-specific verifier (not yet implemented).
        match proof.quote_type {
            QUOTE_TYPE_HOST_MEASURED | QUOTE_TYPE_DEV_SOFTWARE => {
                if !proof.raw_quote.windows(32).any(|w| w == nonce_bytes) {
                    return Err(AgentError::Attestation(
                        "nonce not found in quote (fail-closed)".into(),
                    ));
                }
                Ok(())
            }
            _ => {
                // Hardware quote types: nonce binding is verified by the
                // hardware-specific verifier. For now, fail-closed.
                Err(AgentError::Attestation(
                    "nonce binding verification not implemented for this quote type (fail-closed)"
                        .into(),
                ))
            }
        }
    }
}

/// A successfully verified guest.
pub struct VerifiedGuest {
    /// The guest's X25519 public key for secret sealing.
    /// This is the sealing target for workload secrets, corresponding to
    /// `AttestationQuote.agent_x25519_pubkey` in identity.proto.
    pub guest_x25519_pubkey: [u8; 32],
}
