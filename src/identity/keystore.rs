// SPDX-License-Identifier: Apache-2.0
//! Sensitive-key storage (Ruling G).
//!
//! The X25519 sealing private key and any delegated signing keys must never
//! sit in plaintext on disk. They are TPM2_Seal'd under an SRK and stored as
//! opaque sealed blobs in fjall. On restart the agent unseals them via the TPM.
//!
//! PCR-binding is flagged as a follow-up with the Lead Architect (AA-4).
//! For now we seal under a fixed PCR selection.

use crate::error::AgentError;
use crate::storage::Storage;
use fleetos_core::attestation::tpm::{SealedBlob, TpmEndpoint, seal_to_pcr, unseal};

/// Default PCR indices used for sealing.
///
/// PCR 0 (firmware), 7 (Secure Boot policy), 9 (kernel).
/// This is a starting point; AA-4 may change it.
const DEFAULT_SEAL_PCRS: &[u8] = &[0, 7, 9];

/// Storage keys inside the `delegation` keyspace.
const KEY_SEALING_KEY_BLOB: &[u8] = b"sealing_key_blob";

/// Abstract interface for storing and retrieving sensitive key material.
///
/// Implementations must guarantee that plaintext key bytes never touch
/// persistent storage.
pub trait SensitiveStore {
    /// Store a plaintext key by sealing it first.
    fn store_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AgentError>;

    /// Retrieve and unseal a previously stored key.
    fn load_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
    ) -> Result<Option<Vec<u8>>, AgentError>;
}

/// TPM-backed sensitive store. Seals under an SRK with a fixed PCR selection.
pub struct TpmSealedStore {
    endpoint: TpmEndpoint,
}

impl TpmSealedStore {
    pub fn new(endpoint: TpmEndpoint) -> Self {
        Self { endpoint }
    }

    /// Generate the X25519 sealing keypair, seal the private half, and
    /// persist it. Returns the public half for use in the join flow.
    ///
    /// Called once, pre-attestation. On subsequent restarts use
    /// `load_sealing_pubkey` instead.
    pub fn generate_and_store_sealing_key(
        &self,
        storage: &Storage,
    ) -> Result<[u8; 32], AgentError> {
        let (secret, public) = fleetos_core::crypto::generate_sealing_keypair();
        // FIX: Use .as_slice() to deref the Zeroizing wrapper into a &[u8]
        self.store_sealed(storage, KEY_SEALING_KEY_BLOB, secret.as_slice())?;
        Ok(public.0)
    }

    /// Load the X25519 sealing private key by unsealing it.
    ///
    /// Returns `None` if no sealed blob exists (first boot).
    pub fn load_sealing_secret(&self, storage: &Storage) -> Result<Option<Vec<u8>>, AgentError> {
        self.load_sealed(storage, KEY_SEALING_KEY_BLOB)
    }
}

impl SensitiveStore for TpmSealedStore {
    fn store_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AgentError> {
        let sealed: SealedBlob = seal_to_pcr(&self.endpoint, plaintext, DEFAULT_SEAL_PCRS)
            .map_err(|e| AgentError::Identity(format!("TPM seal failed: {e}")))?;

        let blob_bytes = postcard::to_allocvec(&sealed).map_err(AgentError::Serialization)?;

        storage
            .delegation
            .insert(key_label, blob_bytes.as_slice())
            .map_err(AgentError::Storage)?;

        Ok(())
    }

    fn load_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
    ) -> Result<Option<Vec<u8>>, AgentError> {
        let raw = storage
            .delegation
            .get(key_label)
            .map_err(AgentError::Storage)?;

        let raw = match raw {
            Some(b) if !b.is_empty() => b,
            _ => return Ok(None),
        };

        let sealed: SealedBlob = postcard::from_bytes(&raw).map_err(AgentError::Serialization)?;

        let plaintext = unseal(&self.endpoint, &sealed)
            .map_err(|e| AgentError::Identity(format!("TPM unseal failed: {e}")))?;

        Ok(Some(plaintext.to_vec()))
    }
}
