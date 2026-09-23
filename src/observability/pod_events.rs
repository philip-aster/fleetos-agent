// SPDX-License-Identifier: Apache-2.0
//! Pod lifecycle events → PodEventService.ReportPodEvents.
//!
//! Reports pod lifecycle events to control. Events include:
//! Pulled, Created, Started, ProbeFailed, BackOff, OOMKilled,
//! Evicting, GracePeriodExpired, FailedScheduling.

use std::time::{SystemTime, UNIX_EPOCH};

use fleetos_core::proto::state::PodEvent;

/// Pod event type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodEventType {
    Pulled,
    Created,
    Started,
    ProbeFailed,
    BackOff,
    OomKilled,
    Evicting,
    GracePeriodExpired,
    FailedScheduling,
}

impl PodEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PodEventType::Pulled => "Pulled",
            PodEventType::Created => "Created",
            PodEventType::Started => "Started",
            PodEventType::ProbeFailed => "ProbeFailed",
            PodEventType::BackOff => "BackOff",
            PodEventType::OomKilled => "OOMKilled",
            PodEventType::Evicting => "Evicting",
            PodEventType::GracePeriodExpired => "GracePeriodExpired",
            PodEventType::FailedScheduling => "FailedScheduling",
        }
    }
}

/// Build a pod event.
pub fn build_pod_event(
    pod_id: &str,
    node_id: &str,
    event_type: PodEventType,
    reason: &str,
    message: &str,
) -> PodEvent {
    PodEvent {
        pod_id: pod_id.to_string(),
        node_id: node_id.to_string(),
        event_type: event_type.as_str().to_string(),
        reason: reason.to_string(),
        message: message.to_string(),
        timestamp_unix: now_unix(),
        count: 1,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
