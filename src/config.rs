use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "FleetOS Host Daemon Node Agent")]
pub struct Cli {
    #[arg(short, long, default_value = "/etc/fleetos/agent.toml")]
    pub config: PathBuf,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    pub node_id: String,
    pub control_plane_endpoint: String,
    pub network_interface: String,
}

impl AgentConfig {
    pub fn load_from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path).unwrap_or_else(|_| {
            format!(
                r#"
                    node_id = "node-local-01"
                    control_plane_endpoint = "http://127.0.0.1:8080"
                    network_interface = "lo"
                    "#
            )
        });

        let config: AgentConfig = toml::from_str(&content)?;
        Ok(config)
    }
}
