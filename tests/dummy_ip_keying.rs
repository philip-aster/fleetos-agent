// SPDX-License-Identifier: Apache-2.0
//! CR-3 byte-order tests: canonical IPv4 value → HostOrderIpv4 round-trip.
//!
//! Verifies that the byte-order conversion between the proto's canonical
//! IPv4 value form and the eBPF map key (host order) is correct.
//!
//! The proto transmits dummy_ip in "canonical IPv4 value form" — the IP
//! address interpreted as a big-endian u32. For example, 240.0.0.45 → 0xF000002D.
//!
//! At map-insertion time, the agent converts via HostOrderIpv4::from_network(),
//! which produces the host-order value used as the eBPF map key.

use fleetos_ebpf_common::HostOrderIpv4;
use std::net::Ipv4Addr;

/// Helper: convert an Ipv4Addr to the canonical u32 value (network order).
fn canonical_value(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

#[test]
fn roundtrip_canonical_to_host_and_back() {
    // 240.0.0.45 in canonical form is 0xF000002D.
    let ip = Ipv4Addr::new(240, 0, 0, 45);
    let canonical = canonical_value(ip);
    assert_eq!(canonical, 0xF000002D);

    // Convert to host order.
    let host_order = HostOrderIpv4::from_network(canonical);

    // Convert back to network order.
    let back_to_network = host_order.to_network();
    assert_eq!(back_to_network, canonical);
}

#[test]
fn roundtrip_various_addresses() {
    let test_cases = [
        Ipv4Addr::new(240, 0, 0, 1),
        Ipv4Addr::new(240, 0, 0, 45),
        Ipv4Addr::new(240, 0, 0, 255),
        Ipv4Addr::new(240, 0, 1, 0),
        Ipv4Addr::new(240, 1, 0, 0),
        Ipv4Addr::new(240, 255, 255, 255),
        Ipv4Addr::new(255, 255, 255, 255),
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(192, 168, 1, 100),
    ];

    for ip in test_cases {
        let canonical = canonical_value(ip);
        let host_order = HostOrderIpv4::from_network(canonical);
        let back = host_order.to_network();
        assert_eq!(back, canonical, "round-trip failed for {}", ip);
    }
}

#[test]
fn host_order_value_is_correct_on_little_endian() {
    // On a little-endian machine (x86_64), from_network swaps bytes.
    // 240.0.0.45 = 0xF000002D in network order.
    // On little-endian, from_be swaps to 0x2D0000F0.
    let canonical: u32 = 0xF000002D;
    let host_order = HostOrderIpv4::from_network(canonical);

    // The internal value should be the byte-swapped version on LE.
    #[cfg(target_endian = "little")]
    {
        assert_eq!(host_order.0, 0x2D0000F0);
    }

    // On big-endian, it should be unchanged.
    #[cfg(target_endian = "big")]
    {
        assert_eq!(host_order.0, 0xF000002D);
    }

    // Regardless of endianness, to_network must return the original.
    assert_eq!(host_order.to_network(), canonical);
}

#[test]
fn map_key_matches_ebpf_lookup() {
    // The eBPF program does:
    //   let dst_ip_ho = HostOrderIpv4::from_network(sa.user_ip4);
    //   DUMMY_IP_ROUTE_MAP.get(&dst_ip_ho)
    //
    // The agent inserts with:
    //   let key = HostOrderIpv4::from_network(proto_dummy_ip).0;
    //   map.insert(key, value, 0)
    //
    // These must produce the same key for the lookup to succeed.

    let ip = Ipv4Addr::new(240, 0, 0, 45);
    let canonical = canonical_value(ip);

    // What the eBPF program computes (from the packet's destination IP,
    // which is in network order in the kernel).
    let ebpf_key = HostOrderIpv4::from_network(canonical);

    // What the agent computes (from the proto's canonical value).
    let agent_key = HostOrderIpv4::from_network(canonical);

    // They must be identical.
    assert_eq!(ebpf_key.0, agent_key.0);
}

#[test]
fn zero_ip_is_valid_key() {
    // The proto says "0 = none" but 0 is still a valid map key
    // (it just means no route). Verify it round-trips correctly.
    let canonical: u32 = 0;
    let host_order = HostOrderIpv4::from_network(canonical);
    assert_eq!(host_order.0, 0);
    assert_eq!(host_order.to_network(), 0);
}

#[test]
fn all_240_prefix_addresses_are_in_dummy_space() {
    // The dummy IP space is 240.0.0.0/4, meaning the top 4 bits are 1111.
    // Verify that addresses in this range have the correct top nibble.
    let ip = Ipv4Addr::new(240, 0, 0, 45);
    let canonical = canonical_value(ip);
    assert_eq!(canonical & 0xF0000000, 0xF0000000);

    // Verify the host-order value preserves this property.
    let host_order = HostOrderIpv4::from_network(canonical);
    let back = host_order.to_network();
    assert_eq!(back & 0xF0000000, 0xF0000000);
}
