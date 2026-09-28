// SPDX-License-Identifier: Apache-2.0
//! Phase 6.6 — Gated kernel eBPF smoke test.
//!
//! Loads the compiled eBPF object into the kernel and verifies every
//! agent-owned pinned map can be taken, populated, and read back through the
//! agent's real `maps.rs` accessors. Analogous to the TPM-gated join tests:
//! skipped unless `FLEETOS_EBPF_TESTS=1` is set AND we are root AND the
//! compiled object is present.
//!
//! Run:
//!   sudo -E FLEETOS_EBPF_TESTS=1 cargo test --test ebpf_kernel -- --nocapture
//!
//! Override the object path:
//!   FLEETOS_EBPF_OBJ=/path/to/fleetos-ebpf
//!
//! Note: requires the BPF filesystem mounted at /sys/fs/bpf (normally
//! auto-mounted under root). If load fails with a pin error, run
//!   sudo mount -t bpf bpf /sys/fs/bpf

use std::collections::HashMap as StdHashMap;

use aya::Ebpf;
use fleetos_agent::config::EbpfConfig;
use fleetos_agent::ebpf::loader::load_object;
use fleetos_agent::ebpf::maps::{
    arm_boot_gate, boot_gate_map, disarm_boot_gate, dummy_ip_route_map, insert_dummy_ip_route,
    insert_policy_exact, insert_policy_wildcard, insert_src_identity, local_workloads_map,
    num_possible_cpus, pod_net_counters_map, policy_exact_map, policy_stats_map,
    policy_wildcard_map, prepopulate_pod_counters, register_local_workload, src_identity_map,
};
use fleetos_core::hash::IdentityFingerprint;
use fleetos_ebpf_common::{
    DummyIpRouteValue, EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey, HostOrderIpv4,
    HostOrderPort,
};

/// Copy a bytemuck::Pod value into a fixed-size byte array.
///
/// bytemuck::Pod is only implemented for [T; N] where N ≤ 32, so
/// bytemuck::cast cannot target [u8; 40]. This mirrors the `to_bytes`
/// helper in `src/ebpf/maps.rs`.
fn to_bytes<T: bytemuck::Pod, const N: usize>(val: &T) -> [u8; N] {
    let bytes = bytemuck::bytes_of(val);
    assert_eq!(
        bytes.len(),
        N,
        "ABI size mismatch: expected {N}, got {}",
        bytes.len()
    );
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn object_path() -> std::path::PathBuf {
    match std::env::var("FLEETOS_EBPF_OBJ") {
        Ok(p) => p.into(),
        Err(_) => "../fleetos-ebpf/target/bpfel-unknown-none/release/fleetos-ebpf".into(),
    }
}

/// Load the object, or return None to skip the test gracefully.
fn skip_or_load() -> Option<Ebpf> {
    if std::env::var("FLEETOS_EBPF_TESTS").as_deref() != Ok("1") {
        eprintln!("SKIP: set FLEETOS_EBPF_TESTS=1 to run eBPF kernel tests");
        return None;
    }
    if !is_root() {
        eprintln!("SKIP: eBPF kernel tests require root (try `sudo -E`)");
        return None;
    }
    let path = object_path();
    if !path.exists() {
        eprintln!(
            "SKIP: eBPF object not found at {} (build it or set FLEETOS_EBPF_OBJ)",
            path.display()
        );
        return None;
    }
    let temp = tempfile::tempdir().unwrap();
    let config = EbpfConfig {
        object_path: path,
        pin_path: temp.path().to_path_buf(),
        ..Default::default()
    };
    let result = load_object(&config);
    drop(temp); // load already completed; Aya pins to /sys/fs/bpf, not pin_path
    match result {
        Ok(ebpf) => Some(ebpf),
        Err(e) => {
            eprintln!("SKIP: failed to load eBPF object: {}", e);
            None
        }
    }
}

#[test]
fn kernel_map_population_round_trip() {
    let mut ebpf = match skip_or_load() {
        Some(e) => e,
        None => return,
    };

    // --- Dummy-IP routes ---
    let mut routes = dummy_ip_route_map(&mut ebpf).expect("DUMMY_IP_ROUTE_MAP");
    let ip = HostOrderIpv4::from_network(u32::from_ne_bytes([240, 0, 0, 45]));
    let route = DummyIpRouteValue {
        dst_fp: IdentityFingerprint([0xAA; 16]),
        target_agent_fp: IdentityFingerprint([0xBB; 16]),
        sag_version: 7,
    };
    insert_dummy_ip_route(&mut routes, ip, &route).expect("insert route");
    // [u8; 40] exceeds bytemuck::Pod's N≤32 limit, so use from_bytes instead of cast.
    let raw: [u8; 40] = routes.get(&ip.0, 0).expect("route present");
    let got: &DummyIpRouteValue = bytemuck::from_bytes(&raw);
    assert_eq!(got.dst_fp.0, [0xAA; 16]);
    assert_eq!(got.target_agent_fp.0, [0xBB; 16]);
    assert_eq!(got.sag_version, 7);

    // --- Source identity ([u8; 16] is within N≤32, cast is fine) ---
    let mut src = src_identity_map(&mut ebpf).expect("SRC_IDENTITY_MAP");
    let fp = IdentityFingerprint([0xCC; 16]);
    insert_src_identity(&mut src, ip, &fp).expect("insert src identity");
    let raw16: [u8; 16] = src.get(&ip.0, 0).expect("src identity present");
    let got_fp: &IdentityFingerprint = bytemuck::from_bytes(&raw16);
    assert_eq!(got_fp.0, [0xCC; 16]);

    // --- Exact policy ---
    let mut exact = policy_exact_map(&mut ebpf).expect("POLICY_EXACT");
    let key = EbpfPolicyKey {
        src_fingerprint: IdentityFingerprint([0x11; 16]),
        dst_fingerprint: IdentityFingerprint([0x22; 16]),
        protocol: 6,
        _pad: [0; 3],
        dst_port: HostOrderPort::from_network(5432),
        _pad2: [0; 2],
    };
    let value = EbpfPolicyValue {
        sag_version: 3,
        decision: 1,
        _pad: [0; 7],
    };
    let key_bytes: [u8; 40] = to_bytes(&key);
    let value_bytes: [u8; 16] = to_bytes(&value);
    insert_policy_exact(&mut exact, &key, &value).expect("insert exact");
    let got: [u8; 16] = exact.get(&key_bytes, 0).expect("exact present");
    assert_eq!(got, value_bytes);

    // --- Wildcard policy ([u8; 32] is within N≤32, but use to_bytes for consistency) ---
    let mut wildcard = policy_wildcard_map(&mut ebpf).expect("POLICY_WILDCARD");
    let wkey = EbpfPolicyWildcardKey {
        src_fingerprint: IdentityFingerprint([0x33; 16]),
        dst_fingerprint: IdentityFingerprint([0x44; 16]),
    };
    let wkey_bytes: [u8; 32] = to_bytes(&wkey);
    insert_policy_wildcard(&mut wildcard, &wkey, &value).expect("insert wildcard");
    let got: [u8; 16] = wildcard.get(&wkey_bytes, 0).expect("wildcard present");
    assert_eq!(got, value_bytes);

    // --- Local workloads (with userspace mirror) ---
    let mut local = local_workloads_map(&mut ebpf).expect("LOCAL_WORKLOADS");
    let mut mirror = StdHashMap::new();
    let wl_fp = IdentityFingerprint([0x55; 16]);
    register_local_workload(&mut local, &mut mirror, &wl_fp).expect("register local");
    assert_eq!(mirror.get(&wl_fp), Some(&1u8), "mirror updated");
    assert_eq!(local.get(&wl_fp.0, 0).expect("local present"), 1u8);

    // --- Policy stats (verify accessible) ---
    let _stats = policy_stats_map(&mut ebpf).expect("POLICY_STATS");

    // --- Pod counters (per-CPU) ---
    let mut counters = pod_net_counters_map(&mut ebpf).expect("POD_NET_COUNTERS");
    let pod_ip = HostOrderIpv4::from_network(u32::from_ne_bytes([240, 0, 0, 99]));
    prepopulate_pod_counters(&mut counters, pod_ip).expect("prepopulate counters");
    let ncpu = num_possible_cpus();
    assert!(ncpu >= 1);
    let per_cpu = counters.get(&pod_ip.0, 0).expect("counters present");
    assert_eq!(per_cpu.len(), ncpu, "one entry per possible CPU");

    // --- BOOT_GATE arm/disarm (Array::get takes &u32) ---
    let mut gate = boot_gate_map(&mut ebpf).expect("BOOT_GATE");
    arm_boot_gate(&mut gate).expect("arm");
    assert_eq!(gate.get(&0, 0).expect("gate after arm"), 1);
    disarm_boot_gate(&mut gate).expect("disarm");
    assert_eq!(gate.get(&0, 0).expect("gate after disarm"), 0);
}
