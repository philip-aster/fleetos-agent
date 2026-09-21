// SPDX-License-Identifier: Apache-2.0
//! Typed eBPF map operations.
//!
//! All map operations use raw byte arrays as the Aya key/value types, with
//! `bytemuck::bytes_of` / `bytemuck::from_bytes` for conversion. This matches
//! the pattern locked in `fleetos-ebpf-smoketest/tests/counter_map.rs` and
//! avoids requiring `fleetos-ebpf-common` types to implement `aya::Pod`
//! (they implement `bytemuck::Pod` instead, since core is `no_std`).
//!
//! AA-2: SOCKHASH and SOCK_PEER_MAP are NOT wired here. The eBPF Lead owns
//! the SockTuple keying fix. The agent leaves those maps alone.

use crate::error::AgentError;
use aya::maps::{Array, HashMap, PerCpuHashMap};
use bytemuck;
use fleetos_core::hash::IdentityFingerprint;
use fleetos_ebpf_common::{
    DummyIpRouteValue, EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, HostOrderIpv4,
    PodNetCounters,
};

// --- Conversion helpers ---

/// Convert a `fleetos-ebpf-common` struct to a fixed-size byte array.
/// Panics if the size doesn't match (which would be a compile-time ABI bug).
fn to_bytes<T: bytemuck::Pod, const N: usize>(val: &T) -> [u8; N] {
    let bytes = bytemuck::bytes_of(val);
    assert_eq!(
        bytes.len(),
        N,
        "ABI size mismatch: expected {} bytes, got {}",
        N,
        bytes.len()
    );
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

/// Convert a fixed-size byte array back to a `fleetos-ebpf-common` struct.
///
/// Used by Batch 5 (policy sync readback) and Batch 6 (route lookups).
#[allow(dead_code)]
fn from_bytes<T: bytemuck::Pod>(bytes: &[u8]) -> &T {
    bytemuck::from_bytes(bytes)
}

// --- Map size constants (must match fleetos-ebpf/src/main.rs) ---

pub const POLICY_EXACT_MAX: u32 = 8192;
pub const POLICY_WILDCARD_MAX: u32 = 4096;
pub const DUMMY_IP_ROUTE_MAX: u32 = 262144;
pub const SRC_IDENTITY_MAX: u32 = 1024;
pub const LOCAL_WORKLOADS_MAX: u32 = 1024;
pub const POD_NET_COUNTERS_MAX: u32 = 4096;
pub const POLICY_STATS_MAX: u32 = 8;
pub const BOOT_GATE_MAX: u32 = 1;

// --- Typed map accessors ---

/// Get the DUMMY_IP_ROUTE_MAP as a typed HashMap.
/// Key: HostOrderIpv4 (u32), Value: DummyIpRouteValue (40 bytes).
pub fn dummy_ip_route_map(
    ebpf: &mut aya::Ebpf,
) -> Result<HashMap<aya::maps::MapData, u32, [u8; 40]>, AgentError> {
    let map = ebpf
        .take_map("DUMMY_IP_ROUTE_MAP")
        .ok_or_else(|| AgentError::Ebpf("DUMMY_IP_ROUTE_MAP missing".into()))?;
    HashMap::try_from(map).map_err(|e| AgentError::Ebpf(format!("DUMMY_IP_ROUTE_MAP: {}", e)))
}

/// Get the SRC_IDENTITY_MAP as a typed HashMap.
/// Key: HostOrderIpv4 (u32), Value: IdentityFingerprint (16 bytes).
pub fn src_identity_map(
    ebpf: &mut aya::Ebpf,
) -> Result<HashMap<aya::maps::MapData, u32, [u8; 16]>, AgentError> {
    let map = ebpf
        .take_map("SRC_IDENTITY_MAP")
        .ok_or_else(|| AgentError::Ebpf("SRC_IDENTITY_MAP missing".into()))?;
    HashMap::try_from(map).map_err(|e| AgentError::Ebpf(format!("SRC_IDENTITY_MAP: {}", e)))
}

/// Get the POLICY_EXACT map as a typed HashMap.
/// Key: EbpfPolicyKey (40 bytes), Value: EbpfPolicyValue (16 bytes).
pub fn policy_exact_map(
    ebpf: &mut aya::Ebpf,
) -> Result<HashMap<aya::maps::MapData, [u8; 40], [u8; 16]>, AgentError> {
    let map = ebpf
        .take_map("POLICY_EXACT")
        .ok_or_else(|| AgentError::Ebpf("POLICY_EXACT missing".into()))?;
    HashMap::try_from(map).map_err(|e| AgentError::Ebpf(format!("POLICY_EXACT: {}", e)))
}

/// Get the POLICY_WILDCARD map as a typed HashMap.
/// Key: EbpfPolicyWildcardKey (32 bytes), Value: EbpfPolicyValue (16 bytes).
pub fn policy_wildcard_map(
    ebpf: &mut aya::Ebpf,
) -> Result<HashMap<aya::maps::MapData, [u8; 32], [u8; 16]>, AgentError> {
    let map = ebpf
        .take_map("POLICY_WILDCARD")
        .ok_or_else(|| AgentError::Ebpf("POLICY_WILDCARD missing".into()))?;
    HashMap::try_from(map).map_err(|e| AgentError::Ebpf(format!("POLICY_WILDCARD: {}", e)))
}

/// Get the LOCAL_WORKLOADS map as a typed HashMap.
/// Key: IdentityFingerprint (16 bytes), Value: bool (u8).
pub fn local_workloads_map(
    ebpf: &mut aya::Ebpf,
) -> Result<HashMap<aya::maps::MapData, [u8; 16], u8>, AgentError> {
    let map = ebpf
        .take_map("LOCAL_WORKLOADS")
        .ok_or_else(|| AgentError::Ebpf("LOCAL_WORKLOADS missing".into()))?;
    HashMap::try_from(map).map_err(|e| AgentError::Ebpf(format!("LOCAL_WORKLOADS: {}", e)))
}

/// Get the BOOT_GATE map as a typed Array.
/// Key: u32 (index 0), Value: u32 (0 = locked, 1 = armed).
pub fn boot_gate_map(ebpf: &mut aya::Ebpf) -> Result<Array<aya::maps::MapData, u32>, AgentError> {
    let map = ebpf
        .take_map("BOOT_GATE")
        .ok_or_else(|| AgentError::Ebpf("BOOT_GATE missing".into()))?;
    Array::try_from(map).map_err(|e| AgentError::Ebpf(format!("BOOT_GATE: {}", e)))
}

/// Get the POD_NET_COUNTERS map as a typed PerCpuHashMap.
/// Key: HostOrderIpv4 (u32), Value: PodNetCounters (32 bytes = [u64; 4]).
pub fn pod_net_counters_map(
    ebpf: &mut aya::Ebpf,
) -> Result<PerCpuHashMap<aya::maps::MapData, u32, [u64; 4]>, AgentError> {
    let map = ebpf
        .take_map("POD_NET_COUNTERS")
        .ok_or_else(|| AgentError::Ebpf("POD_NET_COUNTERS missing".into()))?;
    PerCpuHashMap::try_from(map).map_err(|e| AgentError::Ebpf(format!("POD_NET_COUNTERS: {}", e)))
}

/// Get the POLICY_STATS map as a typed Array.
/// Key: u32 (index), Value: u64 (counter).
pub fn policy_stats_map(
    ebpf: &mut aya::Ebpf,
) -> Result<Array<aya::maps::MapData, u64>, AgentError> {
    let map = ebpf
        .take_map("POLICY_STATS")
        .ok_or_else(|| AgentError::Ebpf("POLICY_STATS missing".into()))?;
    Array::try_from(map).map_err(|e| AgentError::Ebpf(format!("POLICY_STATS: {}", e)))
}

// --- Map population helpers ---

/// Insert a dummy-IP route entry into DUMMY_IP_ROUTE_MAP.
///
/// Rule #1: `dst_fp` and `target_agent_fp` MUST be computed via
/// `IdentityFingerprint::of(id, role)`. Never `of_with_ordinal`.
pub fn insert_dummy_ip_route(
    map: &mut HashMap<aya::maps::MapData, u32, [u8; 40]>,
    dummy_ip: HostOrderIpv4,
    route: &DummyIpRouteValue,
) -> Result<(), AgentError> {
    let key = dummy_ip.0; // u32 in host order
    let value: [u8; 40] = to_bytes(route);
    map.insert(key, value, 0)
        .map_err(|e| AgentError::Ebpf(format!("DUMMY_IP_ROUTE_MAP insert: {}", e)))
}

/// Insert a source-identity entry into SRC_IDENTITY_MAP.
pub fn insert_src_identity(
    map: &mut HashMap<aya::maps::MapData, u32, [u8; 16]>,
    src_ip: HostOrderIpv4,
    fingerprint: &IdentityFingerprint,
) -> Result<(), AgentError> {
    let key = src_ip.0;
    let value: [u8; 16] = fingerprint.0;
    map.insert(key, value, 0)
        .map_err(|e| AgentError::Ebpf(format!("SRC_IDENTITY_MAP insert: {}", e)))
}

/// Insert an exact policy entry into POLICY_EXACT.
pub fn insert_policy_exact(
    map: &mut HashMap<aya::maps::MapData, [u8; 40], [u8; 16]>,
    key: &EbpfPolicyKey,
    value: &EbpfPolicyValue,
) -> Result<(), AgentError> {
    let key_bytes: [u8; 40] = to_bytes(key);
    let value_bytes: [u8; 16] = to_bytes(value);
    map.insert(key_bytes, value_bytes, 0)
        .map_err(|e| AgentError::Ebpf(format!("POLICY_EXACT insert: {}", e)))
}

/// Insert a wildcard policy entry into POLICY_WILDCARD.
pub fn insert_policy_wildcard(
    map: &mut HashMap<aya::maps::MapData, [u8; 32], [u8; 16]>,
    key: &EbpfPolicyWildcardKey,
    value: &EbpfPolicyValue,
) -> Result<(), AgentError> {
    let key_bytes: [u8; 32] = to_bytes(key);
    let value_bytes: [u8; 16] = to_bytes(value);
    map.insert(key_bytes, value_bytes, 0)
        .map_err(|e| AgentError::Ebpf(format!("POLICY_WILDCARD insert: {}", e)))
}

/// Register a local workload in LOCAL_WORKLOADS.
///
/// Also updates the userspace mirror (AA-7).
pub fn register_local_workload(
    map: &mut HashMap<aya::maps::MapData, [u8; 16], u8>,
    mirror: &mut std::collections::HashMap<IdentityFingerprint, u8>,
    fingerprint: &IdentityFingerprint,
) -> Result<(), AgentError> {
    let key: [u8; 16] = fingerprint.0;
    map.insert(key, 1u8, 0)
        .map_err(|e| AgentError::Ebpf(format!("LOCAL_WORKLOADS insert: {}", e)))?;

    // AA-7: Keep the userspace mirror in sync.
    mirror.insert(*fingerprint, 1);

    Ok(())
}

/// Unregister a local workload from LOCAL_WORKLOADS.
pub fn unregister_local_workload(
    map: &mut HashMap<aya::maps::MapData, [u8; 16], u8>,
    mirror: &mut std::collections::HashMap<IdentityFingerprint, u8>,
    fingerprint: &IdentityFingerprint,
) -> Result<(), AgentError> {
    let key: [u8; 16] = fingerprint.0;
    map.remove(&key)
        .map_err(|e| AgentError::Ebpf(format!("LOCAL_WORKLOADS remove: {}", e)))?;

    // AA-7: Keep the userspace mirror in sync.
    mirror.remove(fingerprint);

    Ok(())
}

/// Arm the BOOT_GATE. Called after all maps are populated and before
/// the guest NIC comes up (EBPF-CR-3 / Q4b).
///
/// The kernel ingress path drops all overlay traffic until this is set to 1.
pub fn arm_boot_gate(map: &mut Array<aya::maps::MapData, u32>) -> Result<(), AgentError> {
    map.set(0, 1u32, 0)
        .map_err(|e| AgentError::Ebpf(format!("BOOT_GATE arm: {}", e)))?;
    tracing::info!("BOOT_GATE armed — overlay ingress now enforced");
    Ok(())
}

/// Disarm the BOOT_GATE. Called during graceful shutdown.
pub fn disarm_boot_gate(map: &mut Array<aya::maps::MapData, u32>) -> Result<(), AgentError> {
    map.set(0, 0u32, 0)
        .map_err(|e| AgentError::Ebpf(format!("BOOT_GATE disarm: {}", e)))?;
    tracing::info!("BOOT_GATE disarmed");
    Ok(())
}

/// Pre-populate a zeroed POD_NET_COUNTERS entry for a workload IP.
///
/// EBPF-CR-5 agent contract: the agent MUST pre-populate entries for every
/// workload IP it wants metered. Missing entries are silently skipped by
/// the kernel — counters never block traffic.
pub fn prepopulate_pod_counters(
    map: &mut PerCpuHashMap<aya::maps::MapData, u32, [u64; 4]>,
    workload_ip: HostOrderIpv4,
) -> Result<(), AgentError> {
    let key = workload_ip.0;
    let zero: PodNetCounters = PodNetCounters {
        tx_bytes: 0,
        tx_packets: 0,
        rx_bytes: 0,
        rx_packets: 0,
    };
    let zero_bytes: [u64; 4] = bytemuck::cast(zero);

    // PerCpuHashMap requires PerCpuValues (one value per CPU).
    let ncpu = num_possible_cpus();
    let values = aya::maps::PerCpuValues::try_from(vec![zero_bytes; ncpu])
        .map_err(|e| AgentError::Ebpf(format!("PerCpuValues: {}", e)))?;

    map.insert(key, values, 0)
        .map_err(|e| AgentError::Ebpf(format!("POD_NET_COUNTERS insert: {}", e)))
}

/// Read the number of possible CPUs from /sys/devices/system/cpu/possible.
///
/// Mirrors the implementation in fleetos-ebpf-smoketest/tests/counter_map.rs.
pub fn num_possible_cpus() -> usize {
    let raw =
        std::fs::read_to_string("/sys/devices/system/cpu/possible").unwrap_or_else(|_| "0".into());
    let mut max = 0usize;
    for part in raw.trim().split(',') {
        let hi = if let Some((lo_str, hi_str)) = part.split_once('-') {
            let lo: usize = lo_str.parse().expect("malformed CPU range lower bound");
            let hi: usize = hi_str.parse().expect("malformed CPU range upper bound");
            assert!(hi >= lo, "CPU range {lo_str}-{hi_str} is inverted");
            hi
        } else {
            part.parse().expect("malformed CPU index")
        };
        max = max.max(hi);
    }
    max + 1
}
