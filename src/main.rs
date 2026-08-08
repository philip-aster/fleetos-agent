mod attestation;
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
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging with safe default fallback
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let args = Cli::parse();
    info!("Starting FleetOS Node Agent Daemon...");

    let config = AgentConfig::load_from_file(&args.config)?;
    info!("Node ID: {}", config.node_id);

    // Hardware Attestation via IdentityService
    let mock_attestor = fleetos_core::attestor::mock::MockHardwareAttestor::new();
    let boot_attestor = attestation::BootAttestor::new(config.control_plane_endpoint.clone());

    let spiffe_id = match boot_attestor.authenticate_host(&mock_attestor).await {
        Ok(id) => id,
        Err(e) => {
            error!(
                "Attestation failed: {}. Fallback to configured Node ID...",
                e
            );
            format!("spiffe://fleetos.mesh/node/{}", config.node_id)
        }
    };

    let _net_mgr = NetworkManager::new();

    // Load embedded eBPF programs into host kernel
    let ebpf_engine = Arc::new(EbpfEngine::load_and_attach(&config.network_interface)?);

    // Initialize IdentitySyncWorker with gRPC endpoint, Node ID, and eBPF engine
    let sync_worker = IdentitySyncWorker::new(
        config.control_plane_endpoint.clone(),
        spiffe_id,
        ebpf_engine.clone(),
    );

    tokio::spawn(async move {
        sync_worker.run_sync_loop().await;
    });

    info!("FleetOS Node Agent operational. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down FleetOS Node Agent...");

    Ok(())
}
