use anyhow::Result;
use std::path::Path;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct HostSystemPressure {
    pub memory_pressure: bool,
    pub available_memory_mb: u64,
    pub total_memory_mb: u64,
    pub psi_some_avg10: f32,
}

pub struct PressureMonitor;

impl PressureMonitor {
    /// Reads /proc/meminfo and PSI metrics to detect node RAM pressure
    pub async fn check_node_pressure(memory_threshold_mb: u64) -> Result<HostSystemPressure> {
        let meminfo = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .unwrap_or_default();

        let mut available_mb = 0;
        let mut total_mb = 0;

        for line in meminfo.lines() {
            if line.starts_with("MemTotal:") {
                total_mb = parse_kb_line(line) / 1024;
            } else if line.starts_with("MemAvailable:") {
                available_mb = parse_kb_line(line) / 1024;
            }
        }

        // Read kernel PSI (Pressure Stall Info) if available
        let psi_some_avg10 = Self::read_psi_memory_avg10().await.unwrap_or(0.0);

        // Pressure triggers if available memory falls below threshold or PSI stall avg10 > 40.0%
        let memory_pressure = available_mb < memory_threshold_mb || psi_some_avg10 > 40.0;

        if memory_pressure {
            warn!(
                "Node RAM pressure detected! Available: {}MB (Threshold: {}MB), PSI avg10: {:.2}%",
                available_mb, memory_threshold_mb, psi_some_avg10
            );
        }

        Ok(HostSystemPressure {
            memory_pressure,
            available_memory_mb: available_mb,
            total_memory_mb: total_mb,
            psi_some_avg10,
        })
    }

    /// Reads kernel Memory Pressure Stall Information from /proc/pressure/memory
    async fn read_psi_memory_avg10() -> Result<f32> {
        let psi_path = Path::new("/proc/pressure/memory");
        if !psi_path.exists() {
            return Ok(0.0);
        }

        let content = tokio::fs::read_to_string(psi_path).await?;
        for line in content.lines() {
            if line.starts_with("some") {
                // Example line: "some avg10=2.45 avg60=1.12 avg300=0.50 total=123456"
                for field in line.split_whitespace() {
                    if let Some(val) = field.strip_prefix("avg10=") {
                        if let Ok(avg) = val.parse::<f32>() {
                            return Ok(avg);
                        }
                    }
                }
            }
        }

        Ok(0.0)
    }
}

fn parse_kb_line(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|val| val.parse::<u64>().ok())
        .unwrap_or(0)
}
