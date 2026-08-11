pub mod metrics_monitor;
pub mod qos;

use anyhow::Result;
use metrics_monitor::PressureMonitor;
use tracing::info;

pub struct EvictionManager {
    memory_threshold_mb: u64,
}

impl EvictionManager {
    pub fn new(memory_threshold_mb: u64) -> Self {
        Self {
            memory_threshold_mb,
        }
    }

    /// Evaluates system pressure and returns whether eviction should be triggered
    pub fn evaluate_eviction_needed(&self) -> Result<bool> {
        let pressure = PressureMonitor::check_node_pressure(self.memory_threshold_mb)?;
        if pressure.memory_pressure {
            info!("EvictionManager: Recommending eviction due to memory pressure");
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
