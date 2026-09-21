// SPDX-License-Identifier: Apache-2.0
//! Node SVID state.
//!
//! Holds the currently-installed node SVID certificate chain, the live
//! `svid_version` (S-10), and a generation counter. The generation counter
//! is bumped on every rotation so TLS channels can detect the swap and
//! rebuild without a restart.
//!
//! The SVID *private key* is not stored here. It lives in the keystore
//! (TPM-sealed per Ruling G). This module only tracks the public-facing
//! state that the rest of the agent needs to read.

use crate::error::AgentError;
use crate::storage::Storage;

/// Storage keys inside the `svid` keyspace.
const KEY_CERT_CHAIN: &[u8] = b"cert_chain";
const KEY_VERSION: &[u8] = b"svid_version";
const KEY_GENERATION: &[u8] = b"generation";
const KEY_INSTALLED: &[u8] = b"installed";

/// In-memory snapshot of the installed node SVID.
///
/// Cheaply cloneable; handed to channel builders so they can detect rotation
/// via the `generation` counter without locking storage.
#[derive(Debug, Clone)]
pub struct SvidState {
    /// DER-encoded certificate chain (leaf first).
    pub cert_chain_der: Vec<Vec<u8>>,
    /// Live SVID version as reported by control (S-10).
    pub svid_version: u64,
    /// Monotonically increasing rotation counter. Bumped on every SVID swap.
    /// TLS channels compare this to decide whether to rebuild.
    pub generation: u64,
}

impl SvidState {
    /// Returns `true` when no SVID has been installed yet.
    pub fn is_none(&self) -> bool {
        self.cert_chain_der.is_empty()
    }
}

impl Default for SvidState {
    fn default() -> Self {
        Self {
            cert_chain_der: Vec::new(),
            svid_version: 0,
            generation: 0,
        }
    }
}

/// Load the persisted SVID state from storage.
///
/// Returns `SvidState::default()` (i.e. "no SVID") when nothing has been
/// persisted yet — the caller then triggers the join flow.
pub fn load(storage: &Storage) -> Result<SvidState, AgentError> {
    let installed_bytes = storage
        .svid
        .get(KEY_INSTALLED)
        .map_err(AgentError::Storage)?;

    let installed: bool = match installed_bytes {
        Some(b) if !b.is_empty() => b[0] == 1,
        _ => false,
    };

    if !installed {
        return Ok(SvidState::default());
    }

    let cert_chain_raw = storage
        .svid
        .get(KEY_CERT_CHAIN)
        .map_err(AgentError::Storage)?
        .ok_or_else(|| {
            AgentError::Identity("SVID marked installed but cert chain missing".into())
        })?;

    let cert_chain_der: Vec<Vec<u8>> =
        postcard::from_bytes(&cert_chain_raw).map_err(AgentError::Serialization)?;

    let version_raw = storage
        .svid
        .get(KEY_VERSION)
        .map_err(AgentError::Storage)?
        .ok_or_else(|| AgentError::Identity("SVID marked installed but version missing".into()))?;
    let svid_version = u64::from_le_bytes(
        version_raw
            .as_ref()
            .try_into()
            .map_err(|_| AgentError::Identity("corrupt svid_version".into()))?,
    );

    let gen_raw = storage
        .svid
        .get(KEY_GENERATION)
        .map_err(AgentError::Storage)?
        .ok_or_else(|| {
            AgentError::Identity("SVID marked installed but generation missing".into())
        })?;
    let generation = u64::from_le_bytes(
        gen_raw
            .as_ref()
            .try_into()
            .map_err(|_| AgentError::Identity("corrupt generation".into()))?,
    );

    Ok(SvidState {
        cert_chain_der,
        svid_version,
        generation,
    })
}

/// Persist a new SVID state, bumping the generation counter.
///
/// Called after a successful join or rotation. The caller supplies the
/// *current* generation so this function can atomically increment it.
pub fn store(
    storage: &Storage,
    cert_chain_der: &[Vec<u8>],
    svid_version: u64,
    current_generation: u64,
) -> Result<SvidState, AgentError> {
    let generation = current_generation.wrapping_add(1);

    let cert_bytes = postcard::to_allocvec(cert_chain_der).map_err(AgentError::Serialization)?;

    storage
        .svid
        .insert(KEY_CERT_CHAIN, cert_bytes.as_slice())
        .map_err(AgentError::Storage)?;
    storage
        .svid
        .insert(KEY_VERSION, &svid_version.to_le_bytes())
        .map_err(AgentError::Storage)?;
    storage
        .svid
        .insert(KEY_GENERATION, &generation.to_le_bytes())
        .map_err(AgentError::Storage)?;
    storage
        .svid
        .insert(KEY_INSTALLED, &[1u8])
        .map_err(AgentError::Storage)?;

    Ok(SvidState {
        cert_chain_der: cert_chain_der.to_vec(),
        svid_version,
        generation,
    })
}

/// Clear the persisted SVID. Used when a rotation fails and we need to
/// force a re-join rather than serve a stale identity.
pub fn clear(storage: &Storage) -> Result<(), AgentError> {
    storage
        .svid
        .insert(KEY_INSTALLED, &[0u8])
        .map_err(AgentError::Storage)?;
    Ok(())
}
