use fleetos_core::PodSpec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

use crate::pod::types::PodPhase;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerStatus {
    pub name: String,
    pub ready: bool,
    pub restart_count: u32,
    pub image: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodStatusReport {
    pub pod_id: String,
    pub namespace: String,
    pub node_id: String,
    pub phase: PodPhase,
    pub vsock_cid: u32,
    pub container_statuses: Vec<ContainerStatus>,
    pub timestamp: u64,
}

pub struct PodStatusEvaluator {
    node_id: String,
}

impl PodStatusEvaluator {
    pub fn new(node_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
        }
    }

    /// Evaluates dynamic state of a Pod MicroVM and returns a telemetry report
    pub fn evaluate_status(
        &self,
        pod: &PodSpec,
        phase: PodPhase,
        vsock_cid: u32,
        container_readiness: Vec<(String, bool)>,
    ) -> PodStatusReport {
        // Map container names to their spec images
        let container_images: HashMap<String, String> = pod
            .containers
            .iter()
            .map(|c| (c.name.clone(), c.image.clone()))
            .collect();

        let container_statuses = container_readiness
            .into_iter()
            .map(|(name, ready)| {
                let image = container_images
                    .get(&name)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());

                ContainerStatus {
                    name,
                    ready,
                    restart_count: 0,
                    image,
                }
            })
            .collect();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PodStatusReport {
            pod_id: pod.id.clone(),
            namespace: pod.namespace.clone(),
            node_id: self.node_id.clone(),
            phase,
            vsock_cid,
            container_statuses,
            timestamp,
        }
    }
}
