// SPDX-License-Identifier: Apache-2.0
//! Reconnecting watch streams for fleetos-control.
//!
//! Subscribes to WatchSag, WatchSchedule, WatchEvents, and WatchRoutes.
//! Tracks `last_known_version` to discard stale frames (Ruling B: every
//! frame is full state, so monotonicity is sufficient).
//!
//! Full implementation lands when we wire the policy and route sync loops
//! in Batches 5 and 6.

// use crate::error::AgentError;

// Placeholder for reconnecting watch streams.
