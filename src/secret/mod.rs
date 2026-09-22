// SPDX-License-Identifier: Apache-2.0
//! Secrets subsystem: fetch, deliver, and replay-protect.
//!
//! Secrets are pull-based and delivery-sealed. A `SealedSecret` is sealed to
//! the agent's current SVID pubkey + version and becomes permanently
//! unreadable once the agent rotates past that version — that's intentional.
//!
//! The flow is:
//!   1. `WatchEvents` delivers a `SecretRotationNotification` (lightweight ping)
//!   2. Agent calls `FetchSecret` (leader-bound, redirect-and-retry)
//!   3. Agent converts proto → core, checks sequence, unseals
//!   4. Agent hands plaintext to the workload (TODO: Batch 10)
//!
//! Replay protection: `SecretSequenceTracker` (Batch 2) enforces
//! strictly-newer-or-reject per `(target, svid_version)`.

pub mod deliver;
pub mod fetch;
