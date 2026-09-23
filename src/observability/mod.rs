// SPDX-License-Identifier: Apache-2.0
//! Observability: flow events and pod lifecycle events.
//!
//! Push-only OTLP export. No inbound scrape endpoints.

pub mod flow_events;
pub mod pod_events;
