// SPDX-License-Identifier: Apache-2.0
//! Shared redirect-and-retry helper (O-1).
//!
//! When `fleetos-control` returns `UNAVAILABLE` with a `leader-dc-address`
//! metadata key, the agent must retarget and retry. This module provides
//! a pure classification function to decide the next action, extracted
//! for testability without a live server.

use std::time::Duration;
use tonic::Status;

/// Maximum number of redirect hops before giving up.
pub const MAX_REDIRECT_HOPS: usize = 5;

/// Base delay for exponential backoff on transient unavailability.
pub const BASE_RETRY_DELAY_MS: u64 = 100;

/// Maximum delay cap for exponential backoff.
pub const MAX_RETRY_DELAY_MS: u64 = 5000;

/// The metadata key used by fleetos-control to signal a leader redirect.
pub const LEADER_DC_ADDRESS_KEY: &str = "leader-dc-address";

/// The action to take after a gRPC call fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryAction {
    /// Retry the same target after a delay (transient unavailability).
    RetrySameTarget { delay: Duration },
    /// Retarget to the new leader address and retry immediately.
    RedirectAndRetry { new_target: String, delay: Duration },
    /// The error is fatal or we exceeded limits; give up.
    GiveUp(String),
}

/// Classify a gRPC error and determine the next retry action.
///
/// `redirect_hops` is the number of consecutive redirects we've taken
/// for this specific logical operation. We cap this to prevent infinite
/// redirect loops in a misconfigured or partitioned cluster.
pub fn classify_error(status: &Status, redirect_hops: usize) -> RetryAction {
    if redirect_hops > MAX_REDIRECT_HOPS {
        return RetryAction::GiveUp(format!(
            "max redirect hops ({}) exceeded",
            MAX_REDIRECT_HOPS
        ));
    }

    if status.code() == tonic::Code::Unavailable {
        // Check for leader redirect metadata
        if let Some(leader_addr_val) = status.metadata().get(LEADER_DC_ADDRESS_KEY) {
            if let Ok(addr) = leader_addr_val.to_str() {
                let addr = addr.trim().to_string();
                if !addr.is_empty() {
                    return RetryAction::RedirectAndRetry {
                        new_target: addr,
                        delay: Duration::from_millis(0), // Immediate redirect
                    };
                }
            }
        }

        // Standard exponential backoff for transient unavailability
        let delay_ms =
            (BASE_RETRY_DELAY_MS * 2u64.pow(redirect_hops as u32)).min(MAX_RETRY_DELAY_MS);

        return RetryAction::RetrySameTarget {
            delay: Duration::from_millis(delay_ms),
        };
    }

    // All other errors are fatal for this operation
    RetryAction::GiveUp(format!(
        "non-retryable gRPC error: {:?} - {}",
        status.code(),
        status.message()
    ))
}
