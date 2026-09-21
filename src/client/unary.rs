// SPDX-License-Identifier: Apache-2.0
//! Unary RPC wrappers for fleetos-control.
//!
//! These wrap the generated tonic clients with our redirect-and-retry
//! logic and SVID-stamping where required.
//!
//! The actual unary methods will be implemented as we need them in
//! later batches (e.g., FetchSecret in Batch 8, SubmitCsr in Batch 9).
//! For now, we provide the structural boundaries.

// use crate::error::AgentError;

// Placeholder for leader-bound unary RPC wrappers.
// When implementing FetchSecret later, it will look roughly like:
//
// pub async fn fetch_secret(
//     client: &mut SecretServiceClient<Channel>,
//     target_spiffe_id: &str,
//     svid_version: u64,
// ) -> Result<SealedSecret, AgentError> {
//     let mut hops = 0;
//     loop {
//         let req = FetchSecretRequest { target_spiffe_id: target_spiffe_id.to_string(), sealed_for_svid_version: svid_version };
//         match client.fetch_secret(req).await {
//             Ok(resp) => return Ok(resp.into_inner()),
//             Err(status) => {
//                 match classify_error(&status, hops) {
//                     RetryAction::RedirectAndRetry { new_target, .. } => {
//                         // retarget client
//                         hops += 1;
//                     }
//                     RetryAction::RetrySameTarget { delay } => {
//                         tokio::time::sleep(delay).await;
//                     }
//                     RetryAction::GiveUp(msg) => return Err(AgentError::Grpc(Status::unavailable(msg))),
//                 }
//             }
//         }
//     }
// }
