// SPDX-License-Identifier: Apache-2.0
//! Cloud Hypervisor MicroVM runtime adapter.
//!
//! Manages Cloud Hypervisor MicroVM lifecycle.
//! Boot-race guard: TC attach + map population must complete before TAP comes up.

use super::WorkloadSpec;
use crate::error::AgentError;

/// VSOCK CID allocation.
pub struct VsockCidAllocator {
    next_cid: u32,
}

impl VsockCidAllocator {
    pub fn new(start_cid: u32) -> Self {
        Self {
            next_cid: start_cid,
        }
    }

    pub fn allocate(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid += 1;
        cid
    }
}

/// Cloud Hypervisor adapter.
pub struct MicroVmAdapter;

impl MicroVmAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Boot a MicroVM.
    ///
    /// Boot-race guard: the caller must have already armed the VmNetGuard
    /// before calling this. TC attach + map population must be complete.
    pub fn boot(&self, _spec: &WorkloadSpec, _vsock_cid: u32) -> Result<u32, AgentError> {
        // TODO: Implement Cloud Hypervisor MicroVM boot.
        // 1. Prepare erofs rootfs from image
        // 2. Set up TAP device (already down)
        // 3. VmNetGuard must be armed (TC attach + maps populated)
        // 4. Bring TAP up
        // 5. Boot Cloud Hypervisor with VSOCK
        // 6. Wait for guest-init attestation
        Err(AgentError::Workload(
            "cloud-hypervisor boot not yet implemented".into(),
        ))
    }

    /// Stop a MicroVM with grace period.
    pub fn stop(&self, _vsock_cid: u32, _grace_period_secs: u64) -> Result<(), AgentError> {
        // TODO: Implement Cloud Hypervisor MicroVM stop.
        // 1. Send shutdown via VSOCK
        // 2. Wait grace period
        // 3. Force kill if still running
        Err(AgentError::Workload(
            "cloud-hypervisor stop not yet implemented".into(),
        ))
    }
}
