// SPDX-License-Identifier: Apache-2.0
//! Phase 6.6 — eBPF map population byte-contract tests.
//!
//! Verifies the byte-level contract between the agent (userspace map writer)
//! and the fleetos-ebpf programs (kernel map readers). Every map key/value is
//! `#[repr(C)]` + `bytemuck::Pod`; the agent writes `bytemuck::bytes_of` bytes
//! (via `ebpf::maps::to_bytes`) and the kernel reads them back with
//! `bytemuck::from_bytes`. If any field offset, size, or byte order drifts,
//! policy enforcement silently breaks, so these layouts are frozen here.
//!
//! Kernel-side enforcement (the programs actually allowing/denying traffic) is
//! covered by `fleetos-ebpf-smoketest` (root + kernel + loaded object). These
//! tests cover the population contract, which needs no kernel.

use bytemuck;
use fleetos_ebpf_common::{
    DummyIpRouteValue, EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, HostOrderIpv4,
    HostOrderPort, IdentityFingerprint, PodNetCounters,
};

// --- Byte-exact layouts: the exact bytes the kernel map lookups see ---

#[test]
fn policy_exact_key_byte_layout_is_frozen() {
    let key = EbpfPolicyKey {
        src_fingerprint: IdentityFingerprint([0xAA; 16]),
        dst_fingerprint: IdentityFingerprint([0xBB; 16]),
        protocol: 6, // TCP
        _pad: [0; 3],
        dst_port: HostOrderPort(80),
        _pad2: [0; 2],
    };
    let bytes: &[u8] = bytemuck::bytes_of(&key);
    assert_eq!(bytes.len(), 40, "EbpfPolicyKey must be exactly 40 bytes");
    assert_eq!(&bytes[0..16], &[0xAA; 16], "src_fingerprint at offset 0");
    assert_eq!(&bytes[16..32], &[0xBB; 16], "dst_fingerprint at offset 16");
    assert_eq!(bytes[32], 6, "protocol at offset 32");
    assert_eq!(&bytes[33..36], &[0, 0, 0], "_pad at offset 33");
    assert_eq!(
        &bytes[36..38],
        &80u16.to_ne_bytes(),
        "dst_port at offset 36 in host byte order"
    );
    assert_eq!(&bytes[38..40], &[0, 0], "_pad2 at offset 38");
}

#[test]
fn policy_wildcard_key_byte_layout_is_frozen() {
    let key = EbpfPolicyWildcardKey {
        src_fingerprint: IdentityFingerprint([0x11; 16]),
        dst_fingerprint: IdentityFingerprint([0x22; 16]),
    };
    let bytes: &[u8] = bytemuck::bytes_of(&key);
    assert_eq!(
        bytes.len(),
        32,
        "EbpfPolicyWildcardKey must be exactly 32 bytes"
    );
    assert_eq!(&bytes[0..16], &[0x11; 16], "src_fingerprint at offset 0");
    assert_eq!(&bytes[16..32], &[0x22; 16], "dst_fingerprint at offset 16");
}

#[test]
fn policy_value_decision_encoding_is_frozen() {
    // decision 1 = allow
    let allow = EbpfPolicyValue {
        sag_version: 42,
        decision: 1,
        _pad: [0; 7],
    };
    let bytes: &[u8] = bytemuck::bytes_of(&allow);
    assert_eq!(bytes.len(), 16, "EbpfPolicyValue must be exactly 16 bytes");
    assert_eq!(
        &bytes[0..8],
        &42u64.to_le_bytes(),
        "sag_version at offset 0, little-endian"
    );
    assert_eq!(bytes[8], 1, "decision=allow at offset 8");
    assert_eq!(&bytes[9..16], &[0; 7], "_pad at offset 9");

    // decision 0 = deny
    let deny = EbpfPolicyValue {
        sag_version: 42,
        decision: 0,
        _pad: [0; 7],
    };
    let bytes: &[u8] = bytemuck::bytes_of(&deny);
    assert_eq!(bytes[8], 0, "decision=deny at offset 8");
}

#[test]
fn dummy_ip_route_value_byte_layout_is_frozen() {
    let route = DummyIpRouteValue {
        dst_fp: IdentityFingerprint([0xCC; 16]),
        target_agent_fp: IdentityFingerprint([0xDD; 16]),
        sag_version: 7,
    };
    let bytes: &[u8] = bytemuck::bytes_of(&route);
    assert_eq!(
        bytes.len(),
        40,
        "DummyIpRouteValue must be exactly 40 bytes"
    );
    assert_eq!(&bytes[0..16], &[0xCC; 16], "dst_fp at offset 0");
    assert_eq!(&bytes[16..32], &[0xDD; 16], "target_agent_fp at offset 16");
    assert_eq!(
        &bytes[32..40],
        &7u64.to_le_bytes(),
        "sag_version at offset 32, little-endian"
    );
}

#[test]
fn pod_net_counters_byte_layout_is_frozen() {
    let counters = PodNetCounters {
        tx_bytes: 100,
        tx_packets: 1,
        rx_bytes: 50,
        rx_packets: 2,
    };
    let bytes: &[u8] = bytemuck::bytes_of(&counters);
    assert_eq!(bytes.len(), 32, "PodNetCounters must be exactly 32 bytes");
    assert_eq!(&bytes[0..8], &100u64.to_le_bytes(), "tx_bytes at offset 0");
    assert_eq!(&bytes[8..16], &1u64.to_le_bytes(), "tx_packets at offset 8");
    assert_eq!(
        &bytes[16..24],
        &50u64.to_le_bytes(),
        "rx_bytes at offset 16"
    );
    assert_eq!(
        &bytes[24..32],
        &2u64.to_le_bytes(),
        "rx_packets at offset 24"
    );
}

// --- ABI size/alignment guards (runtime complement to assert_layouts) ---

#[test]
fn abi_sizes_and_alignments_match_frozen_layout() {
    use core::mem::{align_of, size_of};
    assert_eq!(size_of::<EbpfPolicyKey>(), 40);
    assert_eq!(
        align_of::<EbpfPolicyKey>(),
        2,
        "HostOrderPort forces align 2, not 1"
    );
    assert_eq!(size_of::<EbpfPolicyWildcardKey>(), 32);
    assert_eq!(align_of::<EbpfPolicyWildcardKey>(), 1);
    assert_eq!(size_of::<EbpfPolicyValue>(), 16);
    assert_eq!(size_of::<DummyIpRouteValue>(), 40);
    assert_eq!(align_of::<DummyIpRouteValue>(), 8);
    assert_eq!(size_of::<PodNetCounters>(), 32);
    assert_eq!(size_of::<IdentityFingerprint>(), 16);
    assert_eq!(align_of::<IdentityFingerprint>(), 1);
}

// --- Byte-order correctness for map keys ---

#[test]
fn host_order_byte_order_round_trip() {
    // Dummy-IP map keys are HostOrderIpv4 (host byte order), converted from
    // the canonical network-order value at insertion time.
    let net_order: u32 = 0xF000002D; // 240.0.0.45
    let host = HostOrderIpv4::from_network(net_order);
    assert_eq!(host.to_network(), net_order, "round-trip must be lossless");

    // Port keys: HostOrderPort stores host-order bytes.
    let port = HostOrderPort::from_network(8080u16.to_be());
    assert_eq!(port.to_network(), 8080u16.to_be());
}

// --- Environment sanity ---

#[test]
fn num_possible_cpus_is_sane() {
    let n = fleetos_agent::ebpf::maps::num_possible_cpus();
    assert!(n >= 1, "must detect at least one possible CPU");
}
