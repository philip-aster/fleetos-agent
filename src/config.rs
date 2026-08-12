use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "FleetOS Host Daemon Node Agent")]
pub struct Cli {
    #[arg(
        short,
        long,
        env = "FLEETOS_CONFIG_PATH",
        default_value = "/etc/fleetos/agent.toml"
    )]
    pub config: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub node_id: String,
    pub control_plane_endpoint: String,
    pub network_interface: String,

    #[serde(default = "default_join_token")]
    pub join_token: String,

    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,

    #[serde(default = "default_vsock_dir")]
    pub vsock_dir: PathBuf,

    #[serde(default = "default_memory_threshold_mb")]
    pub memory_threshold_mb: u64,
}

fn default_join_token() -> String {
    "cluster-bootstrap-token".to_string()
}

fn default_work_dir() -> PathBuf {
    PathBuf::from("/var/lib/fleetos")
}

fn default_vsock_dir() -> PathBuf {
    PathBuf::from("/run/fleetos/vsock")
}

fn default_memory_threshold_mb() -> u64 {
    512
}

impl AgentConfig {
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = if path.exists() {
            info!("Loading node config from path: {}", path.display());
            std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read configuration file: {}", path.display()))?
        } else {
            info!(
                "Config path '{}' not found. Falling back to default configuration.",
                path.display()
            );
            r#"
            node_id = "node-local-01"
            control_plane_endpoint = "http://127.0.0.1:8080"
            network_interface = "lo"
            join_token = "cluster-bootstrap-token"
            memory_threshold_mb = 512
            "#
            .to_string()
        };

        let config: AgentConfig =
            toml::from_str(&content).context("Failed to deserialize TOML configuration")?;

        Ok(config)
    }
}
