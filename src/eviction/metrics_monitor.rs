use anyhow::Result;
use std::fs;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct HostSystemPressure {
    pub memory_pressure: bool,
    pub available_memory_mb: u64,
    pub total_memory_mb: u64,
}

pub struct PressureMonitor;

impl PressureMonitor {
    /// Reads /proc/meminfo to check system RAM threshold
    pub fn check_node_pressure(memory_threshold_mb: u64) -> Result<HostSystemPressure> {
        let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
        let mut available_mb = 0;
        let mut total_mb = 0;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total_mb = parse_kb_line(line) / 1024;
            } else if line.starts_with("MemAvailable:") {
                available_mb = parse_kb_line(line) / 1024;
            }
        }

        let memory_pressure = available_mb < memory_threshold_mb;
        if memory_pressure {
            warn!(
                "Node RAM pressure detected! Available: {}MB (Threshold: {}MB)",
                available_mb, memory_threshold_mb
            );
        }

        Ok(HostSystemPressure {
            memory_pressure,
            available_memory_mb: available_mb,
            total_memory_mb: total_mb,
        })
    }
}

fn parse_kb_line(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|val| val.parse::<u64>().ok())
        .unwrap_or(0)
}
