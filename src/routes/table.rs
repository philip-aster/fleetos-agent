// SPDX-License-Identifier: Apache-2.0
//! Route table management: RouteUpdate → eBPF map mutations.
//!
//! Ruling B: every `RouteUpdate` frame is full state. The agent computes the
//! desired route set, diffs against the currently tracked routes, and
//! produces insert/delete mutations.
//!
//! Rule #1: all fingerprints are computed via `IdentityFingerprint::of(id, role)`.
//! Never `of_with_ordinal`. This is enforced by using only the `of` constructor.
//!
//! CR-3: dummy_ip is transmitted in canonical IPv4 value form (network order).
//! Consumers convert via `HostOrderIpv4::from_network()` at map-insertion time.

use crate::error::AgentError;
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::state::RouteUpdate;
use fleetos_core::spiffe::{SpiffeId, WorkloadRole};
use fleetos_ebpf_common::{DummyIpRouteValue, HostOrderIpv4};
use std::collections::HashSet;

/// Tracks the current state of routes in the eBPF maps.
///
/// The agent maintains this as a userspace mirror of what's in the kernel
/// maps. It's the source of truth for the diff computation.
#[derive(Debug, Clone)]
pub struct RouteSyncState {
    /// The current route version we've applied.
    pub current_version: u64,
    /// Dummy IPs currently in DUMMY_IP_ROUTE_MAP (host-order u32 keys).
    pub dummy_ip_keys: HashSet<u32>,
    /// Fingerprints currently in LOCAL_WORKLOADS.
    pub local_workload_fps: HashSet<IdentityFingerprint>,
}

impl RouteSyncState {
    pub fn new() -> Self {
        Self {
            current_version: 0,
            dummy_ip_keys: HashSet::new(),
            local_workload_fps: HashSet::new(),
        }
    }
}

/// A single route mutation to apply to the eBPF maps.
#[derive(Clone)]
pub enum RouteMutation {
    /// Insert or update a DUMMY_IP_ROUTE_MAP entry.
    InsertRoute {
        key: HostOrderIpv4,
        value: DummyIpRouteValue,
    },
    /// Delete a DUMMY_IP_ROUTE_MAP entry.
    DeleteRoute { key: HostOrderIpv4 },
    /// Add a fingerprint to LOCAL_WORKLOADS.
    AddLocalWorkload { fingerprint: IdentityFingerprint },
    /// Remove a fingerprint from LOCAL_WORKLOADS.
    RemoveLocalWorkload { fingerprint: IdentityFingerprint },
}

/// Mutations to apply to the eBPF maps.
#[derive(Clone, Default)]
pub struct RouteMutations {
    pub mutations: Vec<RouteMutation>,
}

impl RouteMutations {
    pub fn is_empty(&self) -> bool {
        self.mutations.is_empty()
    }
}

/// Process a `RouteUpdate` and compute the mutations needed.
///
/// Returns `None` if the update is stale (version <= current).
///
/// `own_node_spiffe_id` is the agent's own node SpiffeId, used to determine
/// which destinations are local (for LOCAL_WORKLOADS).
pub fn process_route_update(
    state: &RouteSyncState,
    update: &RouteUpdate,
    own_node_spiffe_id: &SpiffeId,
) -> Result<Option<RouteMutations>, AgentError> {
    // Ruling B: version monotonicity check. Discard stale frames.
    if update.version <= state.current_version {
        tracing::debug!(
            incoming = update.version,
            current = state.current_version,
            "discarding stale RouteUpdate"
        );
        return Ok(None);
    }

    let mut mutations = RouteMutations::default();
    let mut desired_dummy_ip_keys: HashSet<u32> = HashSet::new();
    let mut desired_local_fps: HashSet<IdentityFingerprint> = HashSet::new();

    for entry in &update.routes {
        // Parse the destination SpiffeId.
        let dst_spiffe: SpiffeId = entry.destination_svid.parse().map_err(|e| {
            AgentError::Policy(format!(
                "invalid destination_svid '{}': {}",
                entry.destination_svid, e
            ))
        })?;

        // Parse the destination role (empty = wildcard/None).
        let dst_role: Option<WorkloadRole> = if entry.destination_role.is_empty() {
            None
        } else {
            Some(
                WorkloadRole::try_from(entry.destination_role.as_str()).map_err(|e| {
                    AgentError::Policy(format!(
                        "invalid destination_role '{}': {}",
                        entry.destination_role, e
                    ))
                })?,
            )
        };

        // Parse the target agent SpiffeId.
        let target_agent_spiffe: SpiffeId = entry.target_agent_svid.parse().map_err(|e| {
            AgentError::Policy(format!(
                "invalid target_agent_svid '{}': {}",
                entry.target_agent_svid, e
            ))
        })?;

        // Rule #1: compute fingerprints via IdentityFingerprint::of.
        // NEVER of_with_ordinal.
        let dst_fp = IdentityFingerprint::of(&dst_spiffe, dst_role.as_ref());
        let target_agent_fp = IdentityFingerprint::of(&target_agent_spiffe, None);

        // CR-3: convert canonical IPv4 value to host order for map key.
        let host_order_ip = HostOrderIpv4::from_network(entry.dummy_ip);
        let map_key = host_order_ip.0;

        desired_dummy_ip_keys.insert(map_key);

        // Build the DUMMY_IP_ROUTE_MAP value.
        let route_value = DummyIpRouteValue {
            dst_fp,
            target_agent_fp,
            sag_version: update.version,
        };

        // Check if this is a new or updated route.
        if !state.dummy_ip_keys.contains(&map_key) {
            mutations.mutations.push(RouteMutation::InsertRoute {
                key: host_order_ip,
                value: route_value,
            });
        }

        // Determine if the destination is local (on this node).
        if target_agent_spiffe == *own_node_spiffe_id {
            desired_local_fps.insert(dst_fp);
            if !state.local_workload_fps.contains(&dst_fp) {
                mutations.mutations.push(RouteMutation::AddLocalWorkload {
                    fingerprint: dst_fp,
                });
            }
        }
    }

    // Deletions: routes in current state but not in desired state.
    for key in &state.dummy_ip_keys {
        if !desired_dummy_ip_keys.contains(key) {
            mutations.mutations.push(RouteMutation::DeleteRoute {
                key: HostOrderIpv4(*key),
            });
        }
    }

    // LOCAL_WORKLOADS removals: fingerprints in current but not desired.
    for fp in &state.local_workload_fps {
        if !desired_local_fps.contains(fp) {
            mutations
                .mutations
                .push(RouteMutation::RemoveLocalWorkload { fingerprint: *fp });
        }
    }

    Ok(Some(mutations))
}

/// Apply mutations to the sync state after they've been applied to the eBPF maps.
///
/// Call this AFTER the mutations have been successfully applied to the kernel
/// maps. This keeps the userspace mirror in sync with the kernel.
pub fn apply_mutations_to_state(
    state: &mut RouteSyncState,
    mutations: &RouteMutations,
    new_version: u64,
) {
    for mutation in &mutations.mutations {
        match mutation {
            RouteMutation::InsertRoute { key, .. } => {
                state.dummy_ip_keys.insert(key.0);
            }
            RouteMutation::DeleteRoute { key } => {
                state.dummy_ip_keys.remove(&key.0);
            }
            RouteMutation::AddLocalWorkload { fingerprint } => {
                state.local_workload_fps.insert(*fingerprint);
            }
            RouteMutation::RemoveLocalWorkload { fingerprint } => {
                state.local_workload_fps.remove(fingerprint);
            }
        }
    }
    state.current_version = new_version;
}

/// Apply route mutations to the eBPF maps.
///
/// This function takes the typed map handles from the EbpfManager and applies
/// the computed mutations. Called after `process_route_update`.
pub fn apply_mutations_to_maps(
    mutations: &RouteMutations,
    dummy_ip_map: &mut aya::maps::HashMap<aya::maps::MapData, u32, [u8; 40]>,
    local_workloads_map: &mut aya::maps::HashMap<aya::maps::MapData, [u8; 16], u8>,
) -> Result<(), AgentError> {
    for mutation in &mutations.mutations {
        match mutation {
            RouteMutation::InsertRoute { key, value } => {
                let value_bytes: [u8; 40] = bytemuck::bytes_of(value)
                    .try_into()
                    .expect("DummyIpRouteValue is 40 bytes");
                dummy_ip_map
                    .insert(key.0, value_bytes, 0)
                    .map_err(|e| AgentError::Ebpf(format!("DUMMY_IP_ROUTE_MAP insert: {}", e)))?;
            }
            RouteMutation::DeleteRoute { key } => {
                dummy_ip_map
                    .remove(&key.0)
                    .map_err(|e| AgentError::Ebpf(format!("DUMMY_IP_ROUTE_MAP remove: {}", e)))?;
            }
            RouteMutation::AddLocalWorkload { fingerprint } => {
                let fp_bytes: [u8; 16] = fingerprint.0;
                local_workloads_map
                    .insert(fp_bytes, 1u8, 0)
                    .map_err(|e| AgentError::Ebpf(format!("LOCAL_WORKLOADS insert: {}", e)))?;
            }
            RouteMutation::RemoveLocalWorkload { fingerprint } => {
                let fp_bytes: [u8; 16] = fingerprint.0;
                local_workloads_map
                    .remove(&fp_bytes)
                    .map_err(|e| AgentError::Ebpf(format!("LOCAL_WORKLOADS remove: {}", e)))?;
            }
        }
    }
    Ok(())
}

// --- SRC_IDENTITY_MAP registration hooks ---
//
// The SRC_IDENTITY_MAP maps workload source IPs to identity fingerprints.
// These hooks are called by the workload lifecycle (Batch 10) when a
// workload is started or stopped on this node.

/// Register a workload's source IP → identity mapping in SRC_IDENTITY_MAP.
///
/// Called when a workload starts on this node. The `source_ip` is the
/// workload's actual IP on the node's network (assigned by container runtime
/// or MicroVM TAP device).
pub fn register_src_identity(
    src_identity_map: &mut aya::maps::HashMap<aya::maps::MapData, u32, [u8; 16]>,
    source_ip: HostOrderIpv4,
    fingerprint: &IdentityFingerprint,
) -> Result<(), AgentError> {
    let fp_bytes: [u8; 16] = fingerprint.0;
    src_identity_map
        .insert(source_ip.0, fp_bytes, 0)
        .map_err(|e| AgentError::Ebpf(format!("SRC_IDENTITY_MAP insert: {}", e)))
}

/// Unregister a workload's source IP from SRC_IDENTITY_MAP.
///
/// Called when a workload stops on this node.
pub fn unregister_src_identity(
    src_identity_map: &mut aya::maps::HashMap<aya::maps::MapData, u32, [u8; 16]>,
    source_ip: HostOrderIpv4,
) -> Result<(), AgentError> {
    src_identity_map
        .remove(&source_ip.0)
        .map_err(|e| AgentError::Ebpf(format!("SRC_IDENTITY_MAP remove: {}", e)))
}
