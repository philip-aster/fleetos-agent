pub mod metrics_monitor;
pub mod qos;

pub use metrics_monitor::PressureMonitor;
pub use qos::QosRanker;

use anyhow::Result;
use fleetos_core::PodSpec;
use tracing::{info, warn};

pub struct EvictionManager {
    memory_threshold_mb: u64,
}

impl EvictionManager {
    pub fn new(memory_threshold_mb: u64) -> Self {
        Self {
            memory_threshold_mb,
        }
    }

    /// Evaluates system pressure asynchronously and returns whether eviction should be triggered
    pub async fn evaluate_eviction_needed(&self) -> Result<bool> {
        let pressure = PressureMonitor::check_node_pressure(self.memory_threshold_mb).await?;
        if pressure.memory_pressure {
            info!("EvictionManager: Recommending eviction due to host memory pressure");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Evaluates host memory pressure and returns candidate pod IDs to evict to resolve the memory deficit
    pub async fn evaluate_eviction_targets(
        &self,
        active_pods: Vec<PodSpec>,
    ) -> Result<Vec<String>> {
        let pressure = PressureMonitor::check_node_pressure(self.memory_threshold_mb).await?;

        if !pressure.memory_pressure {
            return Ok(Vec::new());
        }

        let memory_deficit_mb = self
            .memory_threshold_mb
            .saturating_sub(pressure.available_memory_mb);

        warn!(
            "EvictionManager: Node under pressure! Memory deficit: {}MB (Available: {}MB, Threshold: {}MB)",
            memory_deficit_mb, pressure.available_memory_mb, self.memory_threshold_mb
        );

        let candidates = QosRanker::select_eviction_candidates(active_pods, memory_deficit_mb);
        info!(
            "EvictionManager: Selected {} pod(s) for eviction",
            candidates.len()
        );

        Ok(candidates)
    }
}

impl Default for EvictionManager {
    fn default() -> Self {
        Self::new(512) // Default 512MB minimum memory buffer
    }
}
