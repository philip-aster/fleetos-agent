pub mod status;
pub mod types;
pub mod worker;

use anyhow::Result;
use fleetos_core::PodSpec;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

use crate::network::NetworkManager;
use crate::runtime::RuntimeSupervisor;
use worker::PodWorkerHandle;

pub struct PodManager {
    network_manager: Arc<NetworkManager>,
    runtime_supervisor: Arc<RuntimeSupervisor>,
    active_pods: Arc<RwLock<HashMap<String, PodWorkerHandle>>>,
}

impl PodManager {
    pub fn new(
        network_manager: Arc<NetworkManager>,
        runtime_supervisor: Arc<RuntimeSupervisor>,
    ) -> Self {
        Self {
            network_manager,
            runtime_supervisor,
            active_pods: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Deploys or updates a Pod on this node across runtime engines
    pub async fn spawn_pod(&self, pod: PodSpec) -> Result<()> {
        let pod_id = pod.id.clone();
        info!("PodManager: Spawning lifecycle worker for Pod '{}'", pod_id);

        let worker_handle = worker::spawn_pod_worker(
            pod,
            self.network_manager.clone(),
            self.runtime_supervisor.clone(),
        );

        let mut pods = self.active_pods.write().await;
        pods.insert(pod_id, worker_handle);

        Ok(())
    }

    /// Stops and terminates a running Pod (MicroVM or OCI task)
    pub async fn terminate_pod(&self, pod_id: &str) -> Result<()> {
        let mut pods = self.active_pods.write().await;
        if let Some(handle) = pods.remove(pod_id) {
            info!("PodManager: Stopping Pod worker for '{}'", pod_id);
            handle.stop().await?;
        }
        Ok(())
    }

    /// Returns the number of currently active pods managed on this host
    pub async fn active_pod_count(&self) -> usize {
        self.active_pods.read().await.len()
    }
}
