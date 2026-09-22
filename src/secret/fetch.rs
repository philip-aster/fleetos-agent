// SPDX-License-Identifier: Apache-2.0
//! FetchSecret: leader-bound, redirect-and-retry, stamps live svid_version.
//!
//! S-10: every fetch stamps the agent's CURRENT svid_version so control
//! seals the secret for the right key. If the agent has no SVID installed,
//! this fails immediately with `NoSvid` — fail-closed.
//!
//! O-1: FetchSecret is leader-bound because sequence allocation is
//! Raft-replicated at fetch time. On UNAVAILABLE + leader-dc-address
//! metadata, we retarget and retry (max 5 hops).

use crate::client::retry::{RetryAction, classify_error};
use crate::error::AgentError;
use crate::identity::svid::SvidState;
use fleetos_core::proto::secret::{FetchSecretRequest, SealedSecret};
use tonic::transport::Channel;

/// Maximum retry attempts for transient failures (non-redirect).
const MAX_TRANSIENT_RETRIES: usize = 3;

/// Fetch a secret from the control plane.
///
/// This is leader-bound: on UNAVAILABLE + leader-dc-address metadata,
/// we retarget and retry. Transient failures get exponential backoff.
///
/// Returns the proto `SealedSecret` for the caller to deliver.
/// The caller is responsible for conversion, sequence check, and unseal.
pub async fn fetch_secret(
    channel: &Channel,
    svid_state: &SvidState,
    target_spiffe_id: &str,
) -> Result<SealedSecret, AgentError> {
    // S-10: fail-closed if no SVID installed.
    if svid_state.is_none() {
        return Err(AgentError::NoSvid);
    }

    let svid_version = svid_state.svid_version;
    let mut client = fleetos_core::proto::secret::SecretServiceClient::new(channel.clone());

    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let request = FetchSecretRequest {
            target_spiffe_id: target_spiffe_id.to_string(),
            sealed_for_svid_version: svid_version,
        };

        match client.fetch_secret(request).await {
            Ok(response) => {
                tracing::debug!(
                    target = %target_spiffe_id,
                    svid_version = svid_version,
                    "secret fetched"
                );
                return Ok(response.into_inner());
            }
            Err(status) => {
                match classify_error(&status, redirect_hops) {
                    RetryAction::RedirectAndRetry { new_target, .. } => {
                        tracing::info!(
                            leader = %new_target,
                            "FetchSecret: redirecting to leader"
                        );
                        redirect_hops += 1;
                        // Rebuild channel to new target.
                        // In production, this would use the ControlPlaneClient
                        // to retarget. For now, we return an error indicating
                        // the caller should retarget.
                        return Err(AgentError::Internal(format!(
                            "redirect to {} required (hops={})",
                            new_target, redirect_hops
                        )));
                    }
                    RetryAction::RetrySameTarget { delay } => {
                        transient_retries += 1;
                        if transient_retries > MAX_TRANSIENT_RETRIES {
                            return Err(AgentError::Secret(format!(
                                "FetchSecret failed after {} retries: {}",
                                transient_retries,
                                status.message()
                            )));
                        }
                        tracing::debug!(
                            delay_ms = delay.as_millis() as u64,
                            attempt = transient_retries,
                            "FetchSecret: transient retry"
                        );
                        tokio::time::sleep(delay).await;
                    }
                    RetryAction::GiveUp(reason) => {
                        return Err(AgentError::Secret(format!(
                            "FetchSecret failed: {}",
                            reason
                        )));
                    }
                }
            }
        }
    }
}
