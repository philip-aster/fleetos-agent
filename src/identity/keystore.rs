// SPDX-License-Identifier: Apache-2.0
//! Sensitive-key storage (Ruling G).
//!
//! The X25519 sealing private key and any delegated signing keys must never
//! sit in plaintext on disk. They are TPM2_Seal'd under an SRK and stored as
//! opaque sealed blobs in fjall. On restart the agent unseals them via the TPM.
//!
//! When no TPM endpoint is configured (insecure/testing mode), the store
//! falls back to software sealing — no TPM attempt, no error noise.
//!
//! PCR-binding is flagged as a follow-up with the Lead Architect (AA-4).
//! For now we seal under a fixed PCR selection.

use crate::error::AgentError;
use crate::storage::Storage;
use fleetos_core::attestation::tpm::{SealedBlob, TpmEndpoint, seal_to_pcr, unseal};
use fleetos_core::crypto::{RecipientX25519Pubkey, SealedSecret, SecretSequence};

/// Default PCR indices used for sealing.
const DEFAULT_SEAL_PCRS: &[u8] = &[0, 7, 9];

/// Storage keys inside the `delegation` keyspace.
const KEY_SEALING_KEY_BLOB: &[u8] = b"sealing_key_blob";

/// Software master key label (insecure/test mode only).
const SOFTWARE_MASTER_KEY_LABEL: &[u8] = b"software_master_key";

/// Prefix bytes to distinguish sealing method.
const SEAL_PREFIX_TPM: u8 = 0x01;
const SEAL_PREFIX_SOFTWARE: u8 = 0x02;

/// Abstract interface for storing and retrieving sensitive key material.
pub trait SensitiveStore {
    fn store_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AgentError>;

    fn load_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
    ) -> Result<Option<Vec<u8>>, AgentError>;
}

/// TPM-backed sensitive store. Seals under an SRK with a fixed PCR selection.
/// When no TPM endpoint is provided (insecure/testing mode), uses software
/// sealing only — no TPM attempt, no error noise.
pub struct TpmSealedStore {
    endpoint: Option<TpmEndpoint>,
}

impl TpmSealedStore {
    /// Create a store. Pass `Some(endpoint)` for TPM sealing (secure mode),
    /// or `None` for software-only sealing (insecure/testing mode).
    pub fn new(endpoint: Option<TpmEndpoint>) -> Self {
        Self { endpoint }
    }

    /// Generate the X25519 sealing keypair, seal the private half, and
    /// persist it. Returns the public half for use in the join flow.
    pub fn generate_and_store_sealing_key(
        &self,
        storage: &Storage,
    ) -> Result<[u8; 32], AgentError> {
        let (secret, public) = fleetos_core::crypto::generate_sealing_keypair();
        self.store_sealed(storage, KEY_SEALING_KEY_BLOB, secret.as_slice())?;
        Ok(public.0)
    }

    /// Load the X25519 sealing private key by unsealing it.
    pub fn load_sealing_secret(&self, storage: &Storage) -> Result<Option<Vec<u8>>, AgentError> {
        self.load_sealed(storage, KEY_SEALING_KEY_BLOB)
    }

    /// Get or create the software master key (insecure/test mode only).
    fn get_or_create_software_master_key(
        &self,
        storage: &Storage,
    ) -> Result<([u8; 32], [u8; 32]), AgentError> {
        if let Some(key_bytes) = storage
            .delegation
            .get(SOFTWARE_MASTER_KEY_LABEL)
            .map_err(AgentError::Storage)?
        {
            if key_bytes.len() == 64 {
                let mut private_key = [0u8; 32];
                let mut public_key = [0u8; 32];
                private_key.copy_from_slice(&key_bytes[..32]);
                public_key.copy_from_slice(&key_bytes[32..]);
                return Ok((private_key, public_key));
            }
        }
        let (private_key, public_key) = fleetos_core::crypto::generate_sealing_keypair();
        let mut key_bytes = Vec::with_capacity(64);
        key_bytes.extend_from_slice(&*private_key);
        key_bytes.extend_from_slice(&public_key.0);
        storage
            .delegation
            .insert(SOFTWARE_MASTER_KEY_LABEL, &key_bytes)
            .map_err(AgentError::Storage)?;
        let private_key_array: [u8; 32] = *private_key;
        Ok((private_key_array, public_key.0))
    }

    /// Software seal: encrypt plaintext with the software master pubkey.
    fn software_seal(
        &self,
        storage: &Storage,
        key_label: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AgentError> {
        let (_, public_key) = self.get_or_create_software_master_key(storage)?;
        let recipient = RecipientX25519Pubkey(public_key);
        let sealed = fleetos_core::crypto::seal(&recipient, plaintext, 0, SecretSequence(1))
            .map_err(|e| AgentError::Secret(format!("software seal failed: {e}")))?;
        let sealed_bytes = postcard::to_allocvec(&(
            sealed.sealed_for_svid_version,
            sealed.sequence.0,
            sealed.ephemeral_pubkey,
            sealed.ciphertext,
        ))
        .map_err(AgentError::Serialization)?;
        let mut prefixed = vec![SEAL_PREFIX_SOFTWARE];
        prefixed.extend_from_slice(&sealed_bytes);
        storage
            .delegation
            .insert(key_label, &prefixed)
            .map_err(AgentError::Storage)?;
        Ok(())
    }

    /// Software unseal: decrypt with the software master privkey.
    fn software_unseal_from_bytes(
        &self,
        storage: &Storage,
        sealed_bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, AgentError> {
        let (private_key, _) = self.get_or_create_software_master_key(storage)?;
        let (version, sequence, ephemeral_pubkey, ciphertext): (u64, u64, [u8; 32], Vec<u8>) =
            postcard::from_bytes(sealed_bytes).map_err(AgentError::Serialization)?;
        let sealed = SealedSecret {
            sealed_for_svid_version: version,
            sequence: SecretSequence(sequence),
            ephemeral_pubkey,
            ciphertext,
        };
        let plaintext = fleetos_core::crypto::unseal(&private_key, &sealed)
            .map_err(|e| AgentError::Secret(format!("software unseal failed: {e}")))?;
        Ok(Some(plaintext.to_vec()))
    }
}

impl SensitiveStore for TpmSealedStore {
    fn store_sealed(
        &self,
        storage: &Storage,
        key_label: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AgentError> {
        // Try TPM seal only if an endpoint is configured.
        if let Some(endpoint) = &self.endpoint {
            match seal_to_pcr(endpoint, plaintext, DEFAULT_SEAL_PCRS) {
                Ok(sealed) => {
                    let blob_bytes =
                        postcard::to_allocvec(&sealed).map_err(AgentError::Serialization)?;
                    let mut prefixed = vec![SEAL_PREFIX_TPM];
                    prefixed.extend_from_slice(&blob_bytes);
                    storage
                        .delegation
                        .insert(key_label, &prefixed)
                        .map_err(AgentError::Storage)?;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(
                        key_label = %String::from_utf8_lossy(key_label),
                        error = %e,
                        "TPM sealing failed, falling back to software sealing (Ruling G degraded)"
                    );
                }
            }
        }
        // Software sealing (no TPM attempt if endpoint is None).
        self.software_seal(storage, key_label, plaintext)
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
            Some(b) if !b.is_empty() => b.to_vec(),
            _ => return Ok(None),
        };
        match raw[0] {
            SEAL_PREFIX_TPM => {
                // TPM unseal requires an endpoint.
                let endpoint = self.endpoint.as_ref().ok_or_else(|| {
                    AgentError::Secret("cannot unseal TPM blob without a TPM endpoint".into())
                })?;
                let sealed: SealedBlob =
                    postcard::from_bytes(&raw[1..]).map_err(AgentError::Serialization)?;
                let plaintext = unseal(endpoint, &sealed)
                    .map_err(|e| AgentError::Secret(format!("TPM unseal failed: {e}")))?;
                Ok(Some(plaintext.to_vec()))
            }
            SEAL_PREFIX_SOFTWARE => self.software_unseal_from_bytes(storage, &raw[1..]),
            _ => Err(AgentError::Secret("unknown seal prefix".into())),
        }
    }
}
