use fleetos_core::PodSpec;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodPhase {
    Pending,
    Booting,
    Running,
    Failed(String),
    Terminated,
}

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
        container_readiness: Vec<(String, bool)>,
    ) -> PodStatusReport {
        let container_statuses = container_readiness
            .into_iter()
            .map(|(name, ready)| ContainerStatus {
                name,
                ready,
                restart_count: 0,
                image: "fleetos/workload:latest".to_string(),
            })
            .collect();

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        PodStatusReport {
            pod_id: pod.id.clone(),
            namespace: "default".to_string(),
            node_id: self.node_id.clone(),
            phase,
            vsock_cid: 3, // Default VSOCK CID
            container_statuses,
            timestamp,
        }
    }
}
