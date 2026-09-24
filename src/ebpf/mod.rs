// SPDX-License-Identifier: Apache-2.0
//! eBPF subsystem: loader, maps, programs, events, counters.
//!
//! The `EbpfManager` owns the loaded eBPF object and all attached programs.
//! It is the single point of contact between the agent and the kernel
//! enforcement plane.

pub mod counters;
pub mod events;
pub mod loader;
pub mod maps;
pub mod net_guard_adapter;
pub mod programs;

use crate::config::EbpfConfig;
use crate::error::AgentError;
use aya::Ebpf;
use fleetos_core::hash::IdentityFingerprint;
use std::collections::HashMap as StdHashMap;

/// Owns the loaded eBPF object, all typed maps, attached programs, and
/// the userspace LOCAL_WORKLOADS mirror.
///
/// Construction order (Batch 12 wiring):
///   1. `EbpfManager::load(config)` — load object, take maps, attach cgroup programs
///   2. Populate policy/route/identity maps via the `maps` module
///   3. For each MicroVM: `programs::VmNetGuard::arm(...)` — TC attach + BOOT_GATE
///   4. Spawn `events::drain_flow_events` loop
///   5. Spawn `counters::PodNetCountersReader` reporting loop
pub struct EbpfManager {
    /// The loaded eBPF object. Programs live here; maps have been taken out.
    pub ebpf: Ebpf,

    /// eBPF configuration from agent.toml.
    pub config: EbpfConfig,

    /// Userspace mirror of LOCAL_WORKLOADS (AA-7).
    /// The kernel map is the source of truth; this is a cache for fast
    /// lookup without a kernel map probe. Must be kept in sync.
    pub local_workloads_mirror: StdHashMap<IdentityFingerprint, u8>,
}

impl EbpfManager {
    /// Load the eBPF object, take all maps, and attach node-wide programs.
    ///
    /// This is called once at agent startup. Per-interface TC attachment
    /// happens later via `VmNetGuard` when MicroVMs boot.
    pub fn load(config: &EbpfConfig) -> Result<Self, AgentError> {
        let ebpf = loader::load_object(config)?;

        tracing::info!(
            object = %config.object_path.display(),
            "eBPF object loaded"
        );

        Ok(Self {
            ebpf,
            config: config.clone(),
            local_workloads_mirror: StdHashMap::new(),
        })
    }

    /// Graceful shutdown: detach all programs.
    ///
    /// Called during agent shutdown. The kernel pins are cleaned up by
    /// the loader on next startup (AA-3).
    pub fn shutdown(&mut self) {
        tracing::info!("detaching eBPF programs");
        // Program links are dropped when EbpfManager is dropped.
        // Aya handles program detachment automatically on drop.
    }
}
