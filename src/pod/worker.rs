use anyhow::Result;
use fleetos_core::{CloudHypervisorConfig, PodSpec};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info};

use crate::runtime::cloud_hypervisor::CloudHypervisorDriver;

#[derive(Debug)]
pub enum PodCommand {
    Stop {
        responder: oneshot::Sender<Result<()>>,
    },
}

pub struct PodWorkerHandle {
    pub pod_id: String,
    tx_cmd: mpsc::Sender<PodCommand>,
}

impl PodWorkerHandle {
    pub async fn stop(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx_cmd.send(PodCommand::Stop { responder: tx }).await;
        rx.await?
    }
}

pub fn spawn_pod_worker(
    pod: PodSpec,
    config: CloudHypervisorConfig,
    driver: Arc<CloudHypervisorDriver>,
) -> PodWorkerHandle {
    let pod_id = pod.id.clone();
    let (tx_cmd, mut rx_cmd) = mpsc::channel::<PodCommand>(16);

    let pod_id_clone = pod_id.clone();
    tokio::spawn(async move {
        info!(
            "[PodWorker:{}] Starting MicroVM boot sequence...",
            pod_id_clone
        );

        if let Err(e) = driver.boot_vm(&pod, &config).await {
            error!("[PodWorker:{}] MicroVM boot failed: {:?}", pod_id_clone, e);
            return;
        }

        info!(
            "[PodWorker:{}] MicroVM is now RUNNING. Listening for signals...",
            pod_id_clone
        );

        while let Some(cmd) = rx_cmd.recv().await {
            match cmd {
                PodCommand::Stop { responder } => {
                    info!("[PodWorker:{}] Received shutdown signal", pod_id_clone);
                    let res = driver.shutdown_vm(&pod_id_clone).await;
                    let _ = responder.send(res);
                    break;
                }
            }
        }

        info!("[PodWorker:{}] Worker loop exited", pod_id_clone);
    });

    PodWorkerHandle { pod_id, tx_cmd }
}
