pub mod status;
pub mod types;
pub mod worker;

use anyhow::Result;
use fleetos_core::PodSpec;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

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

        // If the pod is already running, terminate the old worker first to release TAP/eBPF resources cleanly
        {
            let mut pods = self.active_pods.write().await;
            if let Some(old_handle) = pods.remove(&pod_id) {
                warn!(
                    "PodManager: Pod '{}' is already running. Stopping existing worker for update...",
                    pod_id
                );
                if let Err(e) = old_handle.stop().await {
                    warn!(
                        "PodManager: Error stopping existing worker for '{}': {:?}",
                        pod_id, e
                    );
                }
            }
        }

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
        let handle = {
            let mut pods = self.active_pods.write().await;
            pods.remove(pod_id)
        };

        if let Some(handle) = handle {
            info!("PodManager: Stopping Pod worker for '{}'", pod_id);
            handle.stop().await?;
        } else {
            warn!(
                "PodManager: Requested termination for pod '{}', but it was not found active",
                pod_id
            );
        }

        Ok(())
    }

    /// Returns a list of active pod IDs running on this node
    pub async fn list_pod_ids(&self) -> Vec<String> {
        self.active_pods.read().await.keys().cloned().collect()
    }

    /// Returns the number of currently active pods managed on this host
    pub async fn active_pod_count(&self) -> usize {
        self.active_pods.read().await.len()
    }
}
