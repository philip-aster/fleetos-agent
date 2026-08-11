pub mod ebpf_stats;

use anyhow::Result;
use ebpf_stats::{EbpfStatsCollector, NetworkMetrics};

pub struct MetricsCollector;

impl MetricsCollector {
    pub fn get_node_telemetry() -> Result<NetworkMetrics> {
        EbpfStatsCollector::collect_network_stats()
    }
}
