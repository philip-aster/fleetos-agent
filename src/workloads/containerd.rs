// SPDX-License-Identifier: Apache-2.0
//! containerd runtime adapter.
//!
//! Manages containerd container lifecycle: OCI spec generation,
//! erofs rootfs prep, /etc/hosts bind-mount, cgroup limits.

use super::WorkloadSpec;
use crate::error::AgentError;

/// containerd adapter.
pub struct ContainerdAdapter;

impl ContainerdAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Boot a container.
    pub fn boot(&self, _spec: &WorkloadSpec) -> Result<u32, AgentError> {
        // TODO: Implement containerd container boot.
        // 1. Generate OCI spec from PodSpec
        // 2. Prepare erofs rootfs from image
        // 3. Set up /etc/hosts bind-mount
        // 4. Apply cgroup limits
        // 5. Start container via containerd API
        Err(AgentError::Workload(
            "containerd boot not yet implemented".into(),
        ))
    }

    /// Stop a container with grace period.
    pub fn stop(&self, _pid: u32, _grace_period_secs: u64) -> Result<(), AgentError> {
        // TODO: Implement containerd container stop.
        // 1. Send SIGTERM
        // 2. Wait grace period
        // 3. Force kill if still running
        Err(AgentError::Workload(
            "containerd stop not yet implemented".into(),
        ))
    }
}
