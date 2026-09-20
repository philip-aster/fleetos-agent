// SPDX-License-Identifier: Apache-2.0
//! Agent error types.
//!
//! `PendingUpstream` is the fail-closed stub: anything blocked on an upstream
//! dependency returns this variant. Callers must treat it as "feature
//! unavailable", never as "empty policy = allow". Default-deny stays intact.

use thiserror::Error;

/// Top-level error type for the fleetos-agent daemon.
#[derive(Debug, Error)]
pub enum AgentError {
    /// An upstream dependency is not yet available. This is the fail-closed
    /// stub — the feature is unavailable, not silently permissive.
    #[error("upstream dependency not yet available: {0}")]
    PendingUpstream(&'static str),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage error: {0}")]
    Storage(#[from] fjall::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("gRPC status error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("gRPC transport error: {0}")]
    GrpcTransport(#[from] tonic::transport::Error),

    #[error("attestation error: {0}")]
    Attestation(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("eBPF error: {0}")]
    Ebpf(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// No SVID is installed. All leader-bound RPCs must fail with this.
    #[error("SVID not installed")]
    NoSvid,

    #[error("join failed: {0}")]
    JoinFailed(String),

    #[error("secret error: {0}")]
    Secret(String),

    #[error("policy error: {0}")]
    Policy(String),

    #[error("workload error: {0}")]
    Workload(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl AgentError {
    /// Returns true if this error represents a feature that is blocked on an
    /// upstream dependency. Callers must treat this as "feature unavailable",
    /// never as "empty = allow".
    pub fn is_pending_upstream(&self) -> bool {
        matches!(self, AgentError::PendingUpstream(_))
    }
}
