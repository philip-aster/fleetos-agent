use crate::runtime::RuntimeDriver;
use anyhow::{Context, Result};
use fleetos_core::proto::state::{
    EventType, WatchRequest, state_service_client::StateServiceClient,
};
use fleetos_core::spiffe::SpiffeId;
use fleetos_core::{PodSpec, RuntimeEngine};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

pub struct WorkloadSyncWorker {
    control_plane_url: String,
    node_id: String,
    runtime: Arc<RuntimeDriver>,
}

impl WorkloadSyncWorker {
    pub fn new(control_plane_url: String, node_id: String, runtime: Arc<RuntimeDriver>) -> Self {
        Self {
            control_plane_url,
            node_id,
            runtime,
        }
    }

    /// Outer loop handles automatic reconnects with exponential backoff if fleetos-control drops
    pub async fn run_sync_loop(&self) {
        info!("Starting FleetOS Workload Pod Sync Worker...");

        let mut backoff = Duration::from_secs(1);

        loop {
            info!(
                "Connecting to StateService for Pod scheduling at {}...",
                self.control_plane_url
            );

            match self.connect_and_stream().await {
                Ok(_) => {
                    info!("Pod watch stream closed gracefully by server. Reconnecting...");
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    error!(
                        "WorkloadSync worker stream error: {}. Retrying in {}s...",
                        e,
                        backoff.as_secs()
                    );
                    sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    /// Establishes the gRPC Watch stream and dispatches PodSpecs to Containerd/CloudHypervisor
    async fn connect_and_stream(&self) -> Result<()> {
        let mut client = StateServiceClient::connect(self.control_plane_url.clone())
            .await
            .context("Failed to connect to fleetos-control StateService")?;

        info!("Subscribing to Pod dispatch updates via Watch API...");

        let spiffe_id = SpiffeId::new_node("fleetos.mesh", "default", &self.node_id).to_uri();
        let request = WatchRequest {
            node_id: self.node_id.clone(),
            spiffe_id,
            start_revision: 0,
            key_prefix: format!("/pods/{}", self.node_id).into_bytes(),
        };

        let mut stream = client
            .watch(request)
            .await
            .context("Failed to open Watch stream on control plane")?
            .into_inner();

        info!("Active gRPC stream established. Directing Pod assignments to runtime drivers...");

        while let Some(watch_resp) = stream.message().await? {
            match EventType::try_from(watch_resp.event_type) {
                Ok(EventType::Put) => match serde_json::from_slice::<PodSpec>(&watch_resp.value) {
                    Ok(pod) => {
                        info!("Received Pod dispatch assignment: '{}'", pod.id);
                        let runtime = self.runtime.clone();

                        tokio::spawn(async move {
                            if let Err(e) = runtime.spawn_pod(&pod).await {
                                error!("Failed to spawn Pod '{}': {}", pod.id, e);
                            }
                        });
                    }
                    Err(e) => {
                        warn!(
                            "Failed to deserialize PodSpec payload from watch event: {}",
                            e
                        );
                    }
                },
                Ok(EventType::Delete) => {
                    let key_str = String::from_utf8_lossy(&watch_resp.key);
                    let pod_id = key_str.split('/').last().unwrap_or("unknown");

                    info!("Received Pod termination command for Pod ID: '{}'", pod_id);
                    let runtime = self.runtime.clone();
                    let pod_id_owned = pod_id.to_string();

                    tokio::spawn(async move {
                        if let Err(e) = runtime.stop_pod(&pod_id_owned).await {
                            error!("Failed to stop Pod '{}': {}", pod_id_owned, e);
                        }
                    });
                }
                _ => {}
            }
        }

        Ok(())
    }
}
