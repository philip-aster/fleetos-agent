// SPDX-License-Identifier: Apache-2.0
//! Tests for the POD_NET_COUNTERS aggregate + rate logic (EBPF-CR-5).
//!
//! These tests port the EXACT test cases from
//! `fleetos-ebpf-common/tests/pod_net_counters_contract.rs` into the agent
//! crate, verifying that the agent's implementation matches the reference.
//!
//! Pure computation tests — no eBPF needed.

use fleetos_agent::ebpf::counters::{AggregatedCounters, aggregate, rate};
use fleetos_ebpf_common::PodNetCounters;

fn counters(tx_b: u64, tx_p: u64, rx_b: u64, rx_p: u64) -> PodNetCounters {
    PodNetCounters {
        tx_bytes: tx_b,
        tx_packets: tx_p,
        rx_bytes: rx_b,
        rx_packets: rx_p,
    }
}

#[test]
fn aggregate_sums_across_cpus() {
    let per_cpu = [
        counters(100, 1, 0, 0),
        counters(50, 2, 10, 1),
        counters(0, 0, 5, 1),
    ];
    let agg = aggregate(&per_cpu);
    assert_eq!(
        agg,
        AggregatedCounters {
            tx_bytes: 150,
            tx_packets: 3,
            rx_bytes: 15,
            rx_packets: 2
        }
    );
}

#[test]
fn rate_computes_per_second() {
    let prev = aggregate(&[counters(0, 0, 0, 0)]);
    let curr = aggregate(&[counters(1000, 10, 500, 5)]);
    let r = rate(&prev, &curr, 10).unwrap();
    assert_eq!(r.tx_bytes_per_sec, 100);
    assert_eq!(r.tx_packets_per_sec, 1);
    assert_eq!(r.rx_bytes_per_sec, 50);
    assert_eq!(r.rx_packets_per_sec, 0); // 5/10 truncates to 0
}

#[test]
fn rate_zero_interval_is_none() {
    let a = aggregate(&[counters(1, 1, 1, 1)]);
    assert!(rate(&a, &a, 0).is_none());
}

#[test]
fn rate_no_change_is_zero() {
    let a = aggregate(&[counters(42, 7, 9, 3)]);
    let r = rate(&a, &a, 5).unwrap();
    assert_eq!(r.tx_bytes_per_sec, 0);
    assert_eq!(r.rx_packets_per_sec, 0);
}

#[test]
fn rate_handles_wraparound() {
    let prev = aggregate(&[counters(u64::MAX - 10, 0, 0, 0)]);
    let curr = aggregate(&[counters(5, 0, 0, 0)]); // wrapped past u64::MAX
    let r = rate(&prev, &curr, 1).unwrap();
    // (5 - (MAX-10)) mod 2^64 == 16
    assert_eq!(r.tx_bytes_per_sec, 16);
}

#[test]
fn aggregate_empty_is_zero() {
    let per_cpu: [PodNetCounters; 0] = [];
    let agg = aggregate(&per_cpu);
    assert_eq!(agg, AggregatedCounters::default());
}

#[test]
fn rate_with_single_cpu() {
    let prev = aggregate(&[counters(100, 10, 50, 5)]);
    let curr = aggregate(&[counters(200, 20, 100, 10)]);
    let r = rate(&prev, &curr, 10).unwrap();
    assert_eq!(r.tx_bytes_per_sec, 10);
    assert_eq!(r.tx_packets_per_sec, 1);
    assert_eq!(r.rx_bytes_per_sec, 5);
    assert_eq!(r.rx_packets_per_sec, 0); // 5/10 truncates
}

#[test]
fn rate_large_interval() {
    let prev = aggregate(&[counters(0, 0, 0, 0)]);
    let curr = aggregate(&[counters(3600, 3600, 3600, 3600)]);
    let r = rate(&prev, &curr, 3600).unwrap();
    assert_eq!(r.tx_bytes_per_sec, 1);
    assert_eq!(r.tx_packets_per_sec, 1);
    assert_eq!(r.rx_bytes_per_sec, 1);
    assert_eq!(r.rx_packets_per_sec, 1);
}
