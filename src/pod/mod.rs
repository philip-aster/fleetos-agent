pub mod status;
pub mod types;
pub mod worker;

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::runtime::cloud_hypervisor::CloudHypervisorDriver;
use worker::PodWorkerHandle;

pub struct PodManager {
    ch_driver: Arc<CloudHypervisorDriver>,
    active_pods: Arc<RwLock<HashMap<String, PodWorkerHandle>>>,
}

impl PodManager {
    pub fn new(base_socket_dir: impl Into<String>) -> Self {
        Self {
            ch_driver: Arc::new(CloudHypervisorDriver::new(base_socket_dir)),
            active_pods: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Deploys or updates a Pod on this node
    pub async fn spawn_pod(
        &self,
        pod: fleetos_core::PodSpec,
        config: fleetos_core::CloudHypervisorConfig,
    ) -> Result<()> {
        let pod_id = pod.id.clone();
        info!("PodManager: Spawning lifecycle worker for Pod '{}'", pod_id);

        let worker_handle = worker::spawn_pod_worker(pod, config, self.ch_driver.clone());

        let mut pods = self.active_pods.write().await;
        pods.insert(pod_id, worker_handle);

        Ok(())
    }

    /// Stops and terminates a running Pod MicroVM
    pub async fn terminate_pod(&self, pod_id: &str) -> Result<()> {
        let mut pods = self.active_pods.write().await;
        if let Some(handle) = pods.remove(pod_id) {
            info!("PodManager: Stopping Pod worker for '{}'", pod_id);
            handle.stop().await?;
        }
        Ok(())
    }
}
