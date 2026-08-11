use serde::{Deserialize, Serialize};

// Re-export core specs from fleetos_core so all agent submodules share ground truth types
pub use fleetos_core::{CloudHypervisorConfig, PodSpec};

/// Quality of Service class assigned to a Pod for resource scheduling & eviction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QosClass {
    Guaranteed,
    Burstable,
    BestEffort,
}

/// Lifecycle state machine for Pod instances managed on this node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PodPhase {
    Pending,
    Booting,
    Running,
    Failed(String),
    Terminated,
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
