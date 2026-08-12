pub mod ebpf_stats;

pub use ebpf_stats::{EbpfStatsCollector, NetworkMetrics};

use anyhow::Result;
use aya::Ebpf;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct MetricsCollector {
    stats_collector: EbpfStatsCollector,
}

impl MetricsCollector {
    pub fn new(ebpf: Arc<Mutex<Ebpf>>) -> Self {
        Self {
            stats_collector: EbpfStatsCollector::new(ebpf),
        }
    }

    /// Collects node-level aggregated network telemetry from kernel eBPF maps
    pub async fn get_node_telemetry(&self) -> Result<NetworkMetrics> {
        self.stats_collector.collect_node_network_stats().await
    }

    /// Collects per-pod network telemetry using the pod's assigned IP address
    pub async fn get_pod_telemetry(&self, pod_ip: Ipv4Addr) -> Result<NetworkMetrics> {
        self.stats_collector.collect_pod_network_stats(pod_ip).await
    }
}
