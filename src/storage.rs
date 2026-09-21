// src/storage.rs
// SPDX-License-Identifier: Apache-2.0
//! Agent persistent storage backed by fjall.
//!
//! Four keyspaces, one per concern:
//! - `svid`        — installed node SVID (cert chain + version + generation)
//! - `secret_state`— per-secret bookkeeping (last-fetched, target fingerprints)
//! - `delegation`  — delegated-signing-key state (Ruling G: never plaintext keys)
//! - `sequences`   — secret-sequence replay tracking (S-10)
//!
//! Ruling G: no private key material ever lives here in plaintext.
//! Sensitive keys are TPM-sealed blobs stored as opaque bytes.

use crate::error::AgentError;
use std::path::Path;

/// Thin wrapper around the fjall database and its four agent keyspaces.
pub struct Storage {
    /// Raw handle kept so we can `persist()` / `flush()` during shutdown.
    db: fjall::Database,
    pub svid: fjall::Keyspace,
    pub secret_state: fjall::Keyspace,
    pub delegation: fjall::Keyspace,
    pub sequences: fjall::Keyspace,
}

impl Storage {
    /// Open (or create) the agent database at `path` and bind all keyspaces.
    pub fn open(path: &Path) -> Result<Self, AgentError> {
        std::fs::create_dir_all(path).map_err(AgentError::Io)?;

        // Use the modern fjall 3.x builder API
        let db = fjall::Database::builder(path)
            .open()
            .map_err(AgentError::Storage)?;

        // FIX: fjall 3.x `keyspace()` takes a closure `FnOnce() -> KeyspaceCreateOptions`.
        // Passing the function item `fjall::KeyspaceCreateOptions::default` (without parentheses)
        // satisfies this bound.
        let svid = db
            .keyspace("svid", fjall::KeyspaceCreateOptions::default)
            .map_err(AgentError::Storage)?;

        let secret_state = db
            .keyspace("secret_state", fjall::KeyspaceCreateOptions::default)
            .map_err(AgentError::Storage)?;

        let delegation = db
            .keyspace("delegation", fjall::KeyspaceCreateOptions::default)
            .map_err(AgentError::Storage)?;

        let sequences = db
            .keyspace("sequences", fjall::KeyspaceCreateOptions::default)
            .map_err(AgentError::Storage)?;

        Ok(Self {
            db,
            svid,
            secret_state,
            delegation,
            sequences,
        })
    }

    /// Flush all pending writes to disk. Called during graceful shutdown.
    pub fn flush(&self) -> Result<(), AgentError> {
        // Provide the required PersistMode argument (SyncAll ensures durability)
        self.db
            .persist(fjall::PersistMode::SyncAll)
            .map_err(AgentError::Storage)?;
        Ok(())
    }
}
