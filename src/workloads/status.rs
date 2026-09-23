// SPDX-License-Identifier: Apache-2.0
//! WorkloadStatusReport builder and reporter.
//!
//! Reports workload liveness/readiness to control.
//! Ruling D: a pod is not `Running` until (started) AND (policy_enforced)
//! AND (router_connected).

use std::time::{SystemTime, UNIX_EPOCH};

use fleetos_core::proto::state::WorkloadStatusReport;

use super::pod_manager::Pod;

/// Build a WorkloadStatusReport from a pod.
pub fn build_status_report(pod: &Pod) -> WorkloadStatusReport {
    WorkloadStatusReport {
        pod_id: pod.pod_id.clone(),
        workload_id: pod.workload_id.clone(),
        tenant_id: pod.tenant_id.clone(),
        ready: pod.is_ready(),
        live: pod.is_live(),
        observed_at_unix: now_unix(),
        restart_count: pod.restart_count,
        started: pod.started,
        policy_enforced: pod.policy_enforced,
        router_connected: pod.router_connected,
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
