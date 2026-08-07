mod config;
mod ebpf_loader;
mod identity_sync;
mod network_manager;

use clap::Parser;
use config::{AgentConfig, Cli};
use ebpf_loader::EbpfEngine;
use identity_sync::IdentitySyncWorker;
use network_manager::NetworkManager;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().or_else(|_| EnvFilter::try_new("info")))
        .init();

    let args = Cli::parse();
    info!("Starting FleetOS Node Agent Daemon...");

    let config = AgentConfig::load_from_file(&args.config)?;
    info!("Node ID: {}", config.node_id);

    let _net_mgr = NetworkManager::new();

    // Load embedded eBPF programs into host kernel (no file path required!)
    let ebpf_engine = Arc::new(EbpfEngine::load_and_attach(&config.network_interface)?);

    let sync_worker = IdentitySyncWorker::new(ebpf_engine.clone());
    tokio::spawn(async move {
        sync_worker.run_sync_loop().await;
    });

    info!("FleetOS Node Agent is operational. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down FleetOS Node Agent...");

    Ok(())
}
