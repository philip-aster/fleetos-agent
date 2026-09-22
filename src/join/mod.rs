// SPDX-License-Identifier: Apache-2.0
//! Join flows: secure (CR-10) and insecure (testing only).
//!
//! The join flow is the agent's first act at runtime. It attests to the
//! control plane, obtains its node SVID, and installs it into storage.
//! After join, the agent switches to mTLS channels for all subsequent RPCs.

pub mod insecure;
pub mod secure;

use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::storage::Storage;

/// Perform the join flow based on the configured mode.
pub async fn perform_join(config: &AgentConfig, storage: &Storage) -> Result<(), AgentError> {
    match config.join.mode {
        crate::config::JoinMode::Secure => secure::perform_secure_join(config, storage).await,
        crate::config::JoinMode::Insecure => insecure::perform_insecure_join(config, storage).await,
    }
}
