use serde::{Deserialize, Serialize};

// Re-export ground-truth core types from fleetos_core so all agent submodules share exact specs
pub use fleetos_core::{CloudHypervisorConfig, PodRole, PodSpec, QosClass, RestartPolicy};

/// Lifecycle state machine for Pod instances managed on this node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodPhase {
    Pending,
    Booting,
    Running,
    Failed(String),
    Terminated,
}

impl PodPhase {
    pub fn is_terminal(&self) -> bool {
        matches!(self, PodPhase::Failed(_) | PodPhase::Terminated)
    }

    pub fn is_running(&self) -> bool {
        matches!(self, PodPhase::Running)
    }
}

/// Dynamic operational status of a Pod on this host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodStatus {
    pub pod_id: String,
    pub phase: PodPhase,
    pub vsock_cid: u32,
    pub tap_interface: Option<String>,
    pub allocated_ip: Option<String>,
}

impl PodStatus {
    pub fn new(pod_id: impl Into<String>, vsock_cid: u32) -> Self {
        Self {
            pod_id: pod_id.into(),
            phase: PodPhase::Pending,
            vsock_cid,
            tap_interface: None,
            allocated_ip: None,
        }
    }
}
