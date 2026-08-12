use anyhow::{Context, Result};
use fleetos_core::PodSpec;
use fleetos_core::proto::state::{
    EventType, WatchRequest, state_service_client::StateServiceClient,
};
use fleetos_core::spiffe::SpiffeId;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tonic::transport::Endpoint;
use tracing::{error, info, warn};

use crate::pod::PodManager;

pub struct WorkloadSyncWorker {
    control_plane_url: String,
    node_id: String,
    pod_manager: Arc<PodManager>,
}

impl WorkloadSyncWorker {
    pub fn new(control_plane_url: String, node_id: String, pod_manager: Arc<PodManager>) -> Self {
        Self {
            control_plane_url,
            node_id,
            pod_manager,
        }
    }

    /// Outer loop handles automatic reconnects with exponential backoff if fleetos-control drops
    pub async fn run_sync_loop(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        info!("Starting FleetOS Workload Pod Sync Worker...");

        let mut backoff = Duration::from_secs(1);

        loop {
            info!(
                "Connecting to StateService for Pod scheduling at {}...",
                self.control_plane_url
            );

            tokio::select! {
                res = self.connect_and_stream() => {
                    match res {
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
                _ = shutdown_rx.recv() => {
                    info!("Shutting down WorkloadSyncWorker loop cleanly...");
                    break;
                }
            }
        }
    }

    /// Establishes the gRPC Watch stream and dispatches PodSpecs to PodManager
    async fn connect_and_stream(&self) -> Result<()> {
        let endpoint = Endpoint::from_shared(self.control_plane_url.clone())?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));

        let mut client = StateServiceClient::connect(endpoint)
            .await
            .context("Failed to connect to fleetos-control StateService")?;

        info!("Subscribing to Pod dispatch updates via Watch API...");

        let spiffe_id = SpiffeId::new_node("fleetos.mesh", "default", &self.node_id).to_uri();
        let request = WatchRequest {
            node_id: self.node_id.clone(),
            spiffe_id,
            start_revision: 0,
            key_prefix: format!("/pods/assigned/{}/", self.node_id).into_bytes(),
        };

        let mut stream = client
            .watch(request)
            .await
            .context("Failed to open Watch stream on control plane")?
            .into_inner();

        info!("Active gRPC stream established. Directing Pod assignments to PodManager...");

        while let Some(watch_resp) = stream.message().await? {
            let event_type = watch_resp.event_type();

            match event_type {
                EventType::Put => match serde_json::from_slice::<PodSpec>(&watch_resp.value) {
                    Ok(pod) => {
                        info!("Received Pod dispatch assignment: '{}'", pod.id);
                        let pod_manager = self.pod_manager.clone();

                        tokio::spawn(async move {
                            if let Err(e) = pod_manager.spawn_pod(pod.clone()).await {
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
                EventType::Delete => {
                    let key_str = String::from_utf8_lossy(&watch_resp.key);
                    let pod_id = key_str.split('/').last().unwrap_or("unknown").to_string();

                    info!("Received Pod termination command for Pod ID: '{}'", pod_id);
                    let pod_manager = self.pod_manager.clone();

                    tokio::spawn(async move {
                        if let Err(e) = pod_manager.terminate_pod(&pod_id).await {
                            error!("Failed to terminate Pod '{}': {}", pod_id, e);
                        }
                    });
                }
                _ => {}
            }
        }

        Ok(())
    }
}
