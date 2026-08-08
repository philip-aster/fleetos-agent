// fleetos-agent/src/identity_sync.rs

use crate::ebpf_loader::EbpfEngine;
use anyhow::{Context, Result};
use fleetos_core::proto::state::{
    EventType, WatchRequest, state_service_client::StateServiceClient,
};
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{error, info, warn};

pub struct IdentitySyncWorker {
    control_plane_url: String,
    node_id: String,
    ebpf_engine: Arc<EbpfEngine>,
}

impl IdentitySyncWorker {
    pub fn new(control_plane_url: String, node_id: String, ebpf_engine: Arc<EbpfEngine>) -> Self {
        Self {
            control_plane_url,
            node_id,
            ebpf_engine,
        }
    }

    /// Outer loop handles automatic reconnects with exponential backoff if fleetos-control drops
    pub async fn run_sync_loop(&self) {
        info!("Starting FleetOS Identity Policy Sync Worker...");

        let mut backoff = Duration::from_secs(1);

        loop {
            info!(
                "Connecting to StateService at {}...",
                self.control_plane_url
            );

            match self.connect_and_stream().await {
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
    }

    /// Establishes the gRPC Watch stream and applies state updates to eBPF maps
    async fn connect_and_stream(&self) -> Result<()> {
        // 1. Establish gRPC channel using fleetos-core's generated client
        let mut client = StateServiceClient::connect(self.control_plane_url.clone())
            .await
            .context("Failed to connect to fleetos-control StateService")?;

        info!("Subscribing to policy state updates via Watch API...");

        // 2. Build watch request for policy keys
        let request = WatchRequest {
            start_revision: 0,
            key_prefix: format!("/policies/{}", self.node_id).into_bytes(),
        };

        let mut stream = client
            .watch(request)
            .await
            .context("Failed to open Watch stream on control plane")?
            .into_inner();

        info!("Active gRPC stream established. Directing updates to eBPF kernel maps...");

        // 3. Process incoming stream events
        while let Some(watch_resp) = stream.message().await? {
            match EventType::try_from(watch_resp.event_type) {
                Ok(EventType::Put) => {
                    // Safety check byte lengths against EbpfPolicyKey and EbpfPolicyValue
                    if watch_resp.key.len() == std::mem::size_of::<EbpfPolicyKey>()
                        && watch_resp.value.len() == std::mem::size_of::<EbpfPolicyValue>()
                    {
                        let mut key_bytes = [0u8; std::mem::size_of::<EbpfPolicyKey>()];
                        let mut val_bytes = [0u8; std::mem::size_of::<EbpfPolicyValue>()];

                        key_bytes.copy_from_slice(&watch_resp.key);
                        val_bytes.copy_from_slice(&watch_resp.value);

                        // Safely transmute slice back to eBPF repr(C) structs
                        let key: EbpfPolicyKey = unsafe { std::mem::transmute(key_bytes) };
                        let value: EbpfPolicyValue = unsafe { std::mem::transmute(val_bytes) };

                        if let Err(e) = self.ebpf_engine.update_policy(key, value).await {
                            error!("Failed to apply dynamic policy to eBPF map: {}", e);
                        } else {
                            info!("Successfully synced policy rule into kernel map!");
                        }
                    } else {
                        warn!("Received invalid byte length for policy key/value in WatchResponse");
                    }
                }
                Ok(EventType::Delete) => {
                    info!("Received policy delete event for key");
                    // Can implement ebpf_engine.delete_policy(key) here when needed
                }
                _ => {}
            }
        }

        Ok(())
    }
}
