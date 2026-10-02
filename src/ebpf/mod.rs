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
use crate::ebpf::loader::load_object;
use crate::error::AgentError;
use aya::Ebpf;
use aya::maps::HashMap;
use fleetos_core::hash::IdentityFingerprint;
use std::collections::HashMap as StdHashMap;

pub struct EbpfManager {
    /// The loaded eBPF object. Programs live here; maps have been taken out.
    pub ebpf: Ebpf,
    /// eBPF configuration from agent.toml.
    pub config: EbpfConfig,
    /// Userspace mirror of LOCAL_WORKLOADS (AA-7).
    pub local_workloads_mirror: StdHashMap<IdentityFingerprint, u8>,
    /// Phase 7.1: Policy maps stored for sync access.
    /// Taken once in load(); accessed under Arc<Mutex<>> lock in sync_policy.
    pub policy_exact: HashMap<aya::maps::MapData, [u8; 40], [u8; 16]>,
    pub policy_wildcard: HashMap<aya::maps::MapData, [u8; 32], [u8; 16]>,
    /// Phase 7.2: Route maps stored for sync access.
    pub dummy_ip_route: HashMap<aya::maps::MapData, u32, [u8; 40]>,
    pub local_workloads: HashMap<aya::maps::MapData, [u8; 16], u8>,
}

impl EbpfManager {
    /// Load the eBPF object and extract maps.
    ///
    /// Phase 7.1: Policy maps (POLICY_EXACT, POLICY_WILDCARD) are taken here
    /// and stored in the struct so sync_policy can access them under the
    /// Arc<Mutex<>> lock without re-taking from the Ebpf object.
    pub fn load(config: &EbpfConfig) -> Result<Self, AgentError> {
        let mut ebpf = load_object(config)?;
        // Take policy maps and store them for sync access.
        let policy_exact = maps::policy_exact_map(&mut ebpf)?;
        let policy_wildcard = maps::policy_wildcard_map(&mut ebpf)?;
        let dummy_ip_route = maps::dummy_ip_route_map(&mut ebpf)?;
        let local_workloads = maps::local_workloads_map(&mut ebpf)?;
        Ok(Self {
            ebpf,
            config: config.clone(),
            local_workloads_mirror: StdHashMap::new(),
            policy_exact,
            policy_wildcard,
            dummy_ip_route,
            local_workloads,
        })
    }
    // ... attach_nodewide_cgroup_programs and check_map_capacity unchanged ...

    /// Graceful shutdown. The `Ebpf` object is dropped when `EbpfManager`
    /// is dropped, which detaches all programs and unloads all maps.
    /// This method exists for explicit shutdown ordering in main.rs.
    pub fn shutdown(&mut self) {
        tracing::info!("eBPF manager shutting down");
        // Ebpf is dropped when EbpfManager is dropped.
    }
}
