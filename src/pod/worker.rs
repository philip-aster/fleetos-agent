use anyhow::Result;
use fleetos_core::PodSpec;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::network::{LocalPodEndpoint, NetworkManager};
use crate::runtime::RuntimeSupervisor;

#[derive(Debug)]
pub enum PodCommand {
    Stop {
        responder: oneshot::Sender<Result<()>>,
    },
}

#[derive(Clone)]
pub struct PodWorkerHandle {
    pub pod_id: String,
    tx_cmd: mpsc::Sender<PodCommand>,
}

impl PodWorkerHandle {
    pub async fn stop(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        if self
            .tx_cmd
            .send(PodCommand::Stop { responder: tx })
            .await
            .is_err()
        {
            anyhow::bail!("Failed to send stop command; worker channel closed");
        }
        rx.await?
    }
}

pub fn spawn_pod_worker(
    pod: PodSpec,
    network_manager: Arc<NetworkManager>,
    runtime_supervisor: Arc<RuntimeSupervisor>,
) -> PodWorkerHandle {
    let pod_id = pod.id.clone();
    let (tx_cmd, mut rx_cmd) = mpsc::channel::<PodCommand>(16);

    let pod_id_clone = pod_id.clone();
    tokio::spawn(async move {
        info!(
            "[PodWorker:{}] Starting pod worker lifecycle...",
            pod_id_clone
        );

        let spiffe_id = pod.role.spiffe_id.clone().unwrap_or_else(|| {
            format!("spiffe://fleetos.mesh/ns/{}/sa/{}", pod.namespace, pod.name)
        });

        // IP allocation logic / TAP interface derivation
        let assigned_ip: Ipv4Addr = "10.244.1.100".parse().unwrap();
        let tap_name = format!(
            "tap-{}",
            &pod_id_clone[..std::cmp::min(10, pod_id_clone.len())]
        );
        let if_index = 42; // TAP interface index from netlink

        // 1. Register with local NetworkManager for same-node eBPF fast-path redirection
        let endpoint = LocalPodEndpoint {
            pod_id: pod_id_clone.clone(),
            spiffe_id: spiffe_id.clone(),
            ip_address: assigned_ip,
            tap_device_name: tap_name.clone(),
            if_index,
        };

        if let Err(e) = network_manager.register_local_pod(endpoint).await {
            error!(
                "[PodWorker:{}] Failed to register local network fast-path: {:?}",
                pod_id_clone, e
            );
            return;
        }

        // 2. Apply default eBPF security ingress rules
        if let Err(e) = network_manager
            .allow_spiffe_traffic(&spiffe_id, &spiffe_id, 8080)
            .await
        {
            warn!(
                "[PodWorker:{}] Could not apply default eBPF traffic policy: {:?}",
                pod_id_clone, e
            );
        }

        // 3. Boot runtime via RuntimeSupervisor (CloudHypervisor / Containerd)
        let ip_str = assigned_ip.to_string();
        info!(
            "[PodWorker:{}] Executing boot sequence via RuntimeSupervisor...",
            pod_id_clone
        );

        if let Err(e) = runtime_supervisor
            .start_pod(&pod, Some(&tap_name), Some(&ip_str))
            .await
        {
            error!("[PodWorker:{}] Runtime boot failed: {:?}", pod_id_clone, e);
            let _ = network_manager.unregister_local_pod(&assigned_ip).await;
            return;
        }

        info!(
            "[PodWorker:{}] Workload is now RUNNING. Listening for signals...",
            pod_id_clone
        );

        // 4. Command loop
        while let Some(cmd) = rx_cmd.recv().await {
            match cmd {
                PodCommand::Stop { responder } => {
                    info!("[PodWorker:{}] Received shutdown signal", pod_id_clone);

                    // Teardown runtime
                    let stop_res = runtime_supervisor.stop_pod(&pod).await;

                    // Unregister local eBPF fast-path
                    let unreg_res = network_manager.unregister_local_pod(&assigned_ip).await;

                    let final_res = stop_res.and(unreg_res);
                    let _ = responder.send(final_res);
                    break;
                }
            }
        }

        info!("[PodWorker:{}] Worker loop exited", pod_id_clone);
    });

    PodWorkerHandle { pod_id, tx_cmd }
}
