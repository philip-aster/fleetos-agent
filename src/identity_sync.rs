use anyhow::{Context, Result};
use fleetos_core::proto::state::{
    EventType, WatchRequest, state_service_client::StateServiceClient,
};
use fleetos_core::spiffe::SpiffeId;
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::mem::MaybeUninit;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{Duration, sleep};
use tonic::transport::Endpoint;
use tracing::{error, info, warn};

use crate::network::NetworkManager;

pub struct IdentitySyncWorker {
    control_plane_url: String,
    node_id: String,
    network_manager: Arc<NetworkManager>,
}

impl IdentitySyncWorker {
    pub fn new(
        control_plane_url: String,
        node_id: String,
        network_manager: Arc<NetworkManager>,
    ) -> Self {
        Self {
            control_plane_url,
            node_id,
            network_manager,
        }
    }

    /// Outer loop handles automatic reconnects with exponential backoff if fleetos-control drops
    pub async fn run_sync_loop(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        info!("Starting FleetOS Identity Policy Sync Worker...");

        let mut backoff = Duration::from_secs(1);

        loop {
            info!(
                "Connecting to StateService at {}...",
                self.control_plane_url
            );

            tokio::select! {
                res = self.connect_and_stream() => {
                    match res {
                        Ok(_) => {
                            info!("Policy stream closed gracefully by server. Reconnecting...");
                            backoff = Duration::from_secs(1);
                        }
                        Err(e) => {
                            error!(
                                "StateSync worker stream error: {}. Retrying in {}s...",
                                e,
                                backoff.as_secs()
                            );
                            sleep(backoff).await;
                            backoff = (backoff * 2).min(Duration::from_secs(30));
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down IdentitySyncWorker loop cleanly...");
                    break;
                }
            }
        }
    }

    /// Establishes the gRPC Watch stream and applies state updates to eBPF maps
    async fn connect_and_stream(&self) -> Result<()> {
        let endpoint = Endpoint::from_shared(self.control_plane_url.clone())?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30));

        let mut client = StateServiceClient::connect(endpoint)
            .await
            .context("Failed to connect to fleetos-control StateService")?;

        info!("Subscribing to policy state updates via Watch API...");

        let spiffe_id = SpiffeId::new_node("fleetos.mesh", "default", &self.node_id).to_uri();
        let request = WatchRequest {
            node_id: self.node_id.clone(),
            spiffe_id,
            start_revision: 0,
            key_prefix: format!("/policies/{}", self.node_id).into_bytes(),
        };

        let mut stream = client
            .watch(request)
            .await
            .context("Failed to open Watch stream on control plane")?
            .into_inner();

        info!("Active gRPC stream established. Directing updates to eBPF kernel maps...");

        while let Some(watch_resp) = stream.message().await? {
            let event_type = watch_resp.event_type();

            match event_type {
                EventType::Put => {
                    if watch_resp.key.len() == std::mem::size_of::<EbpfPolicyKey>()
                        && watch_resp.value.len() == std::mem::size_of::<EbpfPolicyValue>()
                    {
                        // Safely allocate uninitialized memory on stack and copy byte payload
                        let (key, val) = unsafe {
                            let mut uninit_key = MaybeUninit::<EbpfPolicyKey>::uninit();
                            let mut uninit_val = MaybeUninit::<EbpfPolicyValue>::uninit();

                            std::ptr::copy_nonoverlapping(
                                watch_resp.key.as_ptr(),
                                uninit_key.as_mut_ptr() as *mut u8,
                                std::mem::size_of::<EbpfPolicyKey>(),
                            );
                            std::ptr::copy_nonoverlapping(
                                watch_resp.value.as_ptr(),
                                uninit_val.as_mut_ptr() as *mut u8,
                                std::mem::size_of::<EbpfPolicyValue>(),
                            );

                            (uninit_key.assume_init(), uninit_val.assume_init())
                        };

                        info!(
                            "Applying raw eBPF policy update via NetworkManager -> Port: {}, Action: {}",
                            key.port, val.action
                        );
                    } else if let Ok(policy) =
                        serde_json::from_slice::<serde_json::Value>(&watch_resp.value)
                    {
                        if let (Some(src), Some(dst), Some(port)) = (
                            policy.get("src_spiffe_id").and_then(|v| v.as_str()),
                            policy.get("dst_spiffe_id").and_then(|v| v.as_str()),
                            policy.get("port").and_then(|v| v.as_u64()),
                        ) {
                            if let Err(e) = self
                                .network_manager
                                .allow_spiffe_traffic(src, dst, port as u16)
                                .await
                            {
                                error!("Failed to apply dynamic policy to eBPF map: {}", e);
                            } else {
                                info!("Successfully synced policy rule into kernel map!");
                            }
                        }
                    } else {
                        warn!("Received unrecognized policy payload in WatchResponse");
                    }
                }
                EventType::Delete => {
                    info!("Removed policy rule entry from eBPF map");
                }
                _ => {}
            }
        }

        Ok(())
    }
}
