// SPDX-License-Identifier: Apache-2.0
//! POD_NET_COUNTERS user-space reader (EBPF-CR-5).
//!
//! The kernel increments per-CPU counters in the TC datapath for allowed
//! overlay traffic. The agent reads these counters periodically, sums
//! across all CPUs, diffs consecutive reads, and computes per-second rates.
//!
//! This module ports the EXACT reference logic from
//! `fleetos-ebpf-common/tests/pod_net_counters_contract.rs`.
//!
//! Agent contract (from fleetos-ebpf README):
//!   1. Pre-populate zeroed entries for every workload IP (done in maps.rs)
//!   2. Read as PerCpu: each get returns one PodNetCounters per possible CPU
//!   3. Sum across CPUs before diffing
//!   4. Diff consecutive samples: rate = (current - previous) / interval
//!   5. Handle wraparound via wrapping_sub
//!   6. Report rates into PodMetrics.net_tx_bytes / net_rx_bytes
//!
//! Coverage: TAP/MicroVM path only. Containerd-path bytes come from the
//! agent's own proxy accounting. Agent merges both sources before reporting.

use crate::error::AgentError;
use aya::maps::PerCpuHashMap;
use bytemuck;
use fleetos_core::proto::fleetos::workload_status_service_client::WorkloadStatusServiceClient;
use fleetos_core::proto::state::PodMetrics;
use fleetos_ebpf_common::PodNetCounters;
use std::time::Duration;
use tokio::sync::watch;
use tonic::transport::Channel;

/// Aggregated counters across all CPUs for a single workload IP.
///
/// Mirrors the `Agg` type in the contract test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AggregatedCounters {
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub rx_packets: u64,
}

/// Per-second rates computed from two consecutive aggregate samples.
///
/// Mirrors the `Rate` type in the contract test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterRates {
    pub tx_bytes_per_sec: u64,
    pub tx_packets_per_sec: u64,
    pub rx_bytes_per_sec: u64,
    pub rx_packets_per_sec: u64,
}

/// Sum the per-CPU samples for one IP into a single aggregate.
///
/// EXACT port from fleetos-ebpf-common/tests/pod_net_counters_contract.rs.
/// Uses saturating_add to handle the (theoretical) case where CPU counters
/// overflow u64. In practice this won't happen, but it's the reference behavior.
pub fn aggregate(per_cpu: &[PodNetCounters]) -> AggregatedCounters {
    per_cpu
        .iter()
        .fold(AggregatedCounters::default(), |a, c| AggregatedCounters {
            tx_bytes: a.tx_bytes.saturating_add(c.tx_bytes),
            tx_packets: a.tx_packets.saturating_add(c.tx_packets),
            rx_bytes: a.rx_bytes.saturating_add(c.rx_bytes),
            rx_packets: a.rx_packets.saturating_add(c.rx_packets),
        })
}

/// Per-second rate between two aggregate samples.
///
/// EXACT port from fleetos-ebpf-common/tests/pod_net_counters_contract.rs.
/// Returns `None` if the interval is zero. `wrapping_sub` tolerates u64
/// counter wraparound.
pub fn rate(
    prev: &AggregatedCounters,
    curr: &AggregatedCounters,
    interval_secs: u64,
) -> Option<CounterRates> {
    if interval_secs == 0 {
        return None;
    }
    Some(CounterRates {
        tx_bytes_per_sec: curr.tx_bytes.wrapping_sub(prev.tx_bytes) / interval_secs,
        tx_packets_per_sec: curr.tx_packets.wrapping_sub(prev.tx_packets) / interval_secs,
        rx_bytes_per_sec: curr.rx_bytes.wrapping_sub(prev.rx_bytes) / interval_secs,
        rx_packets_per_sec: curr.rx_packets.wrapping_sub(prev.rx_packets) / interval_secs,
    })
}

/// Stateful reader that tracks previous aggregates for rate computation.
pub struct PodNetCountersReader {
    /// Previous aggregate per workload IP.
    previous: std::collections::HashMap<u32, AggregatedCounters>,
}

impl PodNetCountersReader {
    pub fn new() -> Self {
        Self {
            previous: std::collections::HashMap::new(),
        }
    }

    /// Read counters for all IPs in the map, aggregate across CPUs,
    /// and compute rates against the previous sample.
    ///
    /// Returns a map of workload IP → rates.
    pub fn read_and_compute_rates(
        &mut self,
        map: &mut PerCpuHashMap<aya::maps::MapData, u32, [u64; 4]>,
        interval_secs: u64,
    ) -> Result<std::collections::HashMap<u32, CounterRates>, AgentError> {
        let mut rates = std::collections::HashMap::new();
        let mut current_aggregates = std::collections::HashMap::new();

        // Iterate over all entries in the map.
        // PerCpuHashMap::iter() returns (key, PerCpuValues<V>).
        for entry in map.iter() {
            let (ip_key, per_cpu_values) =
                entry.map_err(|e| AgentError::Ebpf(format!("POD_NET_COUNTERS iter: {}", e)))?;

            // Convert each per-CPU [u64; 4] back to PodNetCounters.
            let per_cpu: Vec<PodNetCounters> = per_cpu_values
                .iter()
                .map(|bytes| bytemuck::cast(*bytes))
                .collect();

            // Sum across all CPUs.
            let agg = aggregate(&per_cpu);
            current_aggregates.insert(ip_key, agg);

            // Compute rate against previous sample.
            if let Some(prev) = self.previous.get(&ip_key) {
                if let Some(r) = rate(prev, &agg, interval_secs) {
                    rates.insert(ip_key, r);
                }
            }
            // If no previous sample, we can't compute a rate yet.
            // The next read will have a baseline.
        }

        // Update previous aggregates for the next read.
        self.previous = current_aggregates;

        Ok(rates)
    }
}

/// Counters reporting loop. Periodically reads POD_NET_COUNTERS,
/// aggregates and computes rates, and sends PodMetrics via ReportPodMetrics.
///
/// Merges TAP-path counters with containerd proxy accounting before reporting.
/// The TAP-path counters come from the eBPF POD_NET_COUNTERS map.
/// The containerd proxy accounting is tracked separately by the agent.
pub struct CountersReporter {
    reader: PodNetCountersReader,
    map: aya::maps::PerCpuHashMap<aya::maps::MapData, u32, [u64; 4]>,
    client: WorkloadStatusServiceClient<Channel>,
    interval: Duration,
    /// Containerd proxy accounting: pod_id -> (tx_bytes, rx_bytes).
    /// Tracked separately from the eBPF counters.
    containerd_accounting: std::collections::HashMap<String, (u64, u64)>,
}

impl CountersReporter {
    pub fn new(
        map: aya::maps::PerCpuHashMap<aya::maps::MapData, u32, [u64; 4]>,
        client: WorkloadStatusServiceClient<Channel>,
        interval: Duration,
    ) -> Self {
        Self {
            reader: PodNetCountersReader::new(),
            map,
            client,
            interval,
            containerd_accounting: std::collections::HashMap::new(),
        }
    }

    /// Record containerd proxy accounting for a pod.
    /// Called by the containerd proxy adapter when it observes traffic.
    pub fn record_containerd_traffic(&mut self, pod_id: &str, tx_bytes: u64, rx_bytes: u64) {
        let entry = self
            .containerd_accounting
            .entry(pod_id.to_string())
            .or_insert((0, 0));
        entry.0 += tx_bytes;
        entry.1 += rx_bytes;
    }

    /// Run the counters reporting loop. Periodically reads rates and sends PodMetrics.
    pub async fn run_reporter_loop(
        mut self,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), crate::error::AgentError> {
        let mut interval = tokio::time::interval(self.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let interval_secs = self.interval.as_secs();

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("counters reporter shutting down");
                        return Ok(());
                    }
                }
                _ = interval.tick() => {
                    self.report_counters(interval_secs).await?;
                }
            }
        }
    }

    /// Read counters, compute rates, and send PodMetrics.
    async fn report_counters(
        &mut self,
        interval_secs: u64,
    ) -> Result<(), crate::error::AgentError> {
        let rates = self
            .reader
            .read_and_compute_rates(&mut self.map, interval_secs)?;

        let window_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for (ip_key, rate) in rates {
            // TODO: Map ip_key to pod_id. For now, use the IP as the pod_id.
            // In production, this would look up the pod_id from the IP.
            let pod_id = format!("{}", ip_key);

            // Merge TAP-path counters with containerd proxy accounting.
            let (containerd_tx, containerd_rx) = self
                .containerd_accounting
                .get(&pod_id)
                .copied()
                .unwrap_or((0, 0));

            let metrics = PodMetrics {
                pod_id,
                cpu_millicores: 0, // TODO: Wire CPU metrics from cgroup.
                memory_bytes: 0,   // TODO: Wire memory metrics from cgroup.
                net_tx_bytes: rate.tx_bytes_per_sec + containerd_tx,
                net_rx_bytes: rate.rx_bytes_per_sec + containerd_rx,
                window_unix,
            };

            match self.client.report_pod_metrics(metrics).await {
                Ok(_ack) => {
                    tracing::debug!("pod metrics sent");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to send pod metrics");
                }
            }
        }

        Ok(())
    }
}
