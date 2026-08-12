use clap::Parser;
use std::sync::Arc;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use fleetos_agent::{
    attestation::BootAttestor,
    config::{AgentConfig, Cli},
    identity_sync::IdentitySyncWorker,
    network::NetworkManager,
    pod::PodManager,
    runtime::RuntimeSupervisor,
    workload_sync::WorkloadSyncWorker,
};

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
    let boot_attestor = BootAttestor::new(config.control_plane_endpoint.clone());

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

    // Initialize NetworkManager for local fast-path eBPF routing
    let network_manager = Arc::new(NetworkManager::new(&config.network_interface));
    if let Err(e) = network_manager.initialize_ebpf().await {
        error!("Failed to initialize eBPF engine: {:?}", e);
    }

    // Initialize RuntimeSupervisor (Containerd + CloudHypervisor drivers)
    let runtime_supervisor = Arc::new(RuntimeSupervisor::new());

    // Initialize PodManager with network manager and runtime supervisor
    let pod_manager = Arc::new(PodManager::new(network_manager.clone(), runtime_supervisor));

    // Initialize IdentitySyncWorker
    let sync_worker = IdentitySyncWorker::new(
        config.control_plane_endpoint.clone(),
        spiffe_id.clone(),
        network_manager.clone(),
    );

    // Initialize WorkloadSyncWorker
    let workload_worker = WorkloadSyncWorker::new(
        config.control_plane_endpoint.clone(),
        config.node_id.clone(),
        pod_manager,
    );

    // Spawn identity & eBPF policy sync worker
    tokio::spawn(async move {
        sync_worker.run_sync_loop().await;
    });

    // Spawn workload pod sync worker
    tokio::spawn(async move {
        workload_worker.run_sync_loop().await;
    });

    info!("FleetOS Node Agent operational. Press Ctrl+C to stop.");
    tokio::signal::ctrl_c().await?;
    info!("Shutting down FleetOS Node Agent...");

    Ok(())
}
