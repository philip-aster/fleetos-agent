// SPDX-License-Identifier: Apache-2.0
//! fleetos-agent entrypoint.
//!
//! Complete runtime wiring:
//!   config → storage → keystore → SVID load/join → client → eBPF →
//!   watch loops → VSOCK attest server → status/observability →
//!   counters reporting → graceful shutdown.

use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tracing_subscriber::EnvFilter;

use fleetos_agent::client::ControlPlaneClient;
use fleetos_agent::client::channels::build_mtls_channel;
use fleetos_agent::config::AgentConfig;
use fleetos_agent::ebpf::EbpfManager;
use fleetos_agent::identity::keystore::TpmSealedStore;
use fleetos_agent::identity::svid;
use fleetos_agent::join;
use fleetos_agent::observability::flow_events::FlowEventsDrainLoop;
use fleetos_agent::observability::pod_events::PodEventReporter;
use fleetos_agent::storage::Storage;
use fleetos_agent::vsock_attest::VsockAttestServer;
use fleetos_agent::vsock_attest::config_push::WorkloadConfigBuilder;
use fleetos_agent::vsock_attest::verify::VsockQuoteVerifier;
use fleetos_agent::workloads::pod_manager::PodManager;
use fleetos_agent::workloads::status::StatusReporter;

#[derive(Parser)]
#[command(name = "fleetos-agent", about = "FleetOS Node Agent")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "agent.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // --- Phase 1: Configuration ---
    let config = match AgentConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config {}: {}", cli.config.display(), e);
            return Err(e.into());
        }
    };

    // Initialize tracing subscriber.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // R-1 fence: insecure join mode must be loudly warned.
    if config.join.mode == fleetos_agent::config::JoinMode::Insecure {
        tracing::warn!("====================================================================");
        if cfg!(feature = "production") {
            tracing::warn!(
                "INSECURE JOIN MODE ENABLED IN A PRODUCTION BUILD via \
                 join.mode = \"insecure\"."
            );
            tracing::warn!(
                "RESIDUAL RISK: join-token possession alone grants cluster \
                 admission. Testing only; never a real deployment."
            );
        } else {
            tracing::warn!(
                "INSECURE JOIN MODE ACTIVE: join-token possession is the only \
                 gate to cluster admission and quote signatures are NOT verified. \
                 TESTING ONLY — never use in a real deployment."
            );
        }
        tracing::warn!("====================================================================");
    }

    tracing::info!(
        config = %cli.config.display(),
        node = %config.node.name,
        trust_domain = %config.node.trust_domain,
        control = %config.control.address,
        "fleetos-agent starting"
    );

    // --- Phase 2: Storage ---
    let storage = Storage::open(&config.storage.fjall_path)?;
    tracing::info!(path = %config.storage.fjall_path.display(), "storage opened");

    // --- Phase 3: Keystore (TPM-sealed) ---
    let tpm_endpoint = config.tpm_endpoint();
    let keystore = TpmSealedStore::new(tpm_endpoint);
    tracing::info!("keystore initialized");

    // --- Phase 4: SVID load or join ---
    let mut svid_state = svid::load(&storage)?;

    if svid_state.is_none() {
        tracing::info!("no SVID found, performing join");

        // Ensure sealing keypair exists (generates if first boot).
        let _sealing_pubkey = keystore.generate_and_store_sealing_key(&storage)?;
        tracing::info!("sealing keypair ready");

        // Perform join (secure or insecure based on config).
        join::perform_join(&config, &storage).await?;
        tracing::info!("join completed successfully");

        // Reload SVID state after join.
        svid_state = svid::load(&storage)?;
    } else {
        tracing::info!(
            svid_version = svid_state.svid_version,
            generation = svid_state.generation,
            "SVID loaded from storage"
        );
    }

    // --- Phase 5: Control plane client (mTLS) ---
    let trust_bundle_pem =
        std::fs::read_to_string(&config.control.trust_bundle_path).map_err(|e| {
            fleetos_agent::error::AgentError::Config(format!("failed to read trust bundle: {}", e))
        })?;

    let private_key_der = keystore.load_sealing_secret(&storage)?.ok_or_else(|| {
        fleetos_agent::error::AgentError::Identity(
            "sealing private key not found in keystore".into(),
        )
    })?;

    let channel = build_mtls_channel(
        &config.control.address,
        &trust_bundle_pem,
        &svid_state.cert_chain_der,
        &private_key_der,
    )
    .await?;
    tracing::info!("mTLS channel established to control plane");

    let _control_client = Arc::new(ControlPlaneClient::new(config.control.address.clone()));

    // --- Phase 6: eBPF ---
    let mut ebpf_manager = EbpfManager::load(&config.ebpf)?;
    tracing::info!(
        object = %config.ebpf.object_path.display(),
        "eBPF object loaded"
    );

    // Attach node-wide cgroup programs.
    let _cgroup_links = fleetos_agent::ebpf::programs::attach_cgroup_programs(
        &mut ebpf_manager.ebpf,
        &config.ebpf.cgroup_path.to_string_lossy(),
    )?;
    tracing::info!(
        cgroup = %config.ebpf.cgroup_path.display(),
        "cgroup programs attached"
    );

    // Take the FLOW_EVENTS ring buffer for observability.
    let flow_events_ring_buf =
        fleetos_agent::ebpf::events::take_flow_events_ringbuf(&mut ebpf_manager.ebpf)?;
    tracing::info!("FLOW_EVENTS ring buffer acquired");

    // Take the POD_NET_COUNTERS map for counters reporting.
    let pod_net_counters_map =
        fleetos_agent::ebpf::maps::pod_net_counters_map(&mut ebpf_manager.ebpf)?;
    tracing::info!("POD_NET_COUNTERS map acquired");

    // --- Phase 7: Shared state ---
    let pod_manager = Arc::new(RwLock::new(PodManager::new()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // --- Phase 8: VSOCK attestation server ---
    let verifier = Arc::new(VsockQuoteVerifier::new());
    let config_builder = Arc::new(WorkloadConfigBuilder::new(config.node.trust_domain.clone()));
    let vsock_server = VsockAttestServer::new(verifier, config_builder);
    let vsock_shutdown_rx = shutdown_rx.clone();
    let vsock_handle = tokio::spawn(async move {
        if let Err(e) = vsock_server.run(vsock_shutdown_rx).await {
            tracing::error!(error = %e, "VSOCK attestation server failed");
        }
    });
    tracing::info!("VSOCK attestation server started");

    // --- Phase 9: Status reporter ---
    let status_client =
        fleetos_core::proto::fleetos::workload_status_service_client::WorkloadStatusServiceClient::new(
            channel.clone(),
        );
    let status_reporter =
        StatusReporter::new(pod_manager.clone(), status_client, Duration::from_secs(15));
    let status_shutdown_rx = shutdown_rx.clone();
    let status_handle = tokio::spawn(async move {
        if let Err(e) = status_reporter.run_reporter_loop(status_shutdown_rx).await {
            tracing::error!(error = %e, "status reporter failed");
        }
    });
    tracing::info!("status reporter started");

    // --- Phase 10: Observability ---
    let flow_drain = FlowEventsDrainLoop::new(flow_events_ring_buf, Duration::from_secs(5));
    let flow_shutdown_rx = shutdown_rx.clone();
    let flow_handle = tokio::spawn(async move {
        if let Err(e) = flow_drain.run_drain_loop(flow_shutdown_rx).await {
            tracing::error!(error = %e, "flow events drain failed");
        }
    });
    tracing::info!("flow events drain started");

    // Pod events reporter.
    let pod_event_client =
        fleetos_core::proto::fleetos::pod_event_service_client::PodEventServiceClient::new(
            channel.clone(),
        );
    let pod_event_reporter = PodEventReporter::new(
        config.node.name.clone(),
        pod_event_client,
        100,
        Duration::from_secs(10),
    );
    let pod_event_shutdown_rx = shutdown_rx.clone();
    let pod_event_handle = tokio::spawn(async move {
        if let Err(e) = pod_event_reporter
            .run_flush_loop(pod_event_shutdown_rx)
            .await
        {
            tracing::error!(error = %e, "pod event reporter failed");
        }
    });
    tracing::info!("pod event reporter started");

    // --- Phase 11: Counters reporter ---
    let counters_client =
        fleetos_core::proto::fleetos::workload_status_service_client::WorkloadStatusServiceClient::new(
            channel.clone(),
        );
    let counters_reporter = fleetos_agent::ebpf::counters::CountersReporter::new(
        pod_net_counters_map,
        counters_client,
        Duration::from_secs(30),
    );
    let counters_shutdown_rx = shutdown_rx.clone();
    let counters_handle = tokio::spawn(async move {
        if let Err(e) = counters_reporter
            .run_reporter_loop(counters_shutdown_rx)
            .await
        {
            tracing::error!(error = %e, "counters reporter failed");
        }
    });
    tracing::info!("counters reporter started");

    // --- Phase 12: Watch loops (SAG, Schedule, Events, Routes) ---
    // These are wired in later batches when the full watch infrastructure is ready.
    // For now, we log that they would be started here.
    tracing::info!("watch loops: SAG, Schedule, Events, Routes (wired in later batches)");

    tracing::info!("fleetos-agent fully initialized and running");

    // --- Phase 13: Wait for shutdown signal ---
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown signal received");

    // --- Phase 14: Graceful shutdown ---
    tracing::info!("beginning graceful shutdown");

    // Signal all tasks to stop.
    let _ = shutdown_tx.send(true);

    // Wait for all tasks to complete.
    let _ = tokio::join!(
        vsock_handle,
        status_handle,
        flow_handle,
        pod_event_handle,
        counters_handle,
    );

    // Detach eBPF programs.
    ebpf_manager.shutdown();
    tracing::info!("eBPF programs detached");

    // Flush storage.
    storage.flush()?;
    tracing::info!("storage flushed");

    tracing::info!("fleetos-agent shutdown complete");
    Ok(())
}
