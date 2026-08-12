use anyhow::Result;
use fleetos_core::{PodSpec, RuntimeEngine};
use tracing::info;

pub mod cloud_hypervisor;
pub mod containerd;

use cloud_hypervisor::CloudHypervisorDriver;
use containerd::ContainerdDriver;

pub struct RuntimeSupervisor {
    cloud_hypervisor: CloudHypervisorDriver,
    containerd: ContainerdDriver,
}

pub type RuntimeManager = RuntimeSupervisor;

impl RuntimeSupervisor {
    pub fn new() -> Self {
        Self {
            cloud_hypervisor: CloudHypervisorDriver::default(),
            containerd: ContainerdDriver::default(),
        }
    }

    /// Allows constructing a RuntimeSupervisor with custom socket paths
    pub fn with_socket_paths(
        ch_base_dir: impl Into<String>,
        containerd_socket: impl Into<String>,
    ) -> Self {
        Self {
            cloud_hypervisor: CloudHypervisorDriver::new(ch_base_dir),
            containerd: ContainerdDriver::new(containerd_socket, "fleetos"),
        }
    }

    /// Boots a workload pod using the specified runtime engine (MicroVM or OCI)
    pub async fn start_pod(
        &self,
        pod: &PodSpec,
        host_iface: Option<&str>,
        assigned_ip: Option<&str>,
    ) -> Result<()> {
        match &pod.runtime {
            RuntimeEngine::CloudHypervisor(cfg) => {
                info!(
                    "[Runtime Supervisor] Launching MicroVM Pod '{}' via CloudHypervisor",
                    pod.id
                );
                self.cloud_hypervisor
                    .boot_vm(pod, cfg, host_iface, assigned_ip)
                    .await?;
            }
            RuntimeEngine::Containerd(cfg) => {
                info!(
                    "[Runtime Supervisor] Launching OCI Pod '{}' via Containerd",
                    pod.id
                );
                self.containerd
                    .create_and_start_pod(pod, cfg, host_iface, assigned_ip)
                    .await?;
            }
        }
        Ok(())
    }

    /// Terminates an active workload pod across runtimes
    pub async fn stop_pod(&self, pod: &PodSpec) -> Result<()> {
        match &pod.runtime {
            RuntimeEngine::CloudHypervisor(_) => {
                self.cloud_hypervisor.shutdown_vm(&pod.id).await?;
            }
            RuntimeEngine::Containerd(_) => {
                self.containerd.stop_pod(&pod.id).await?;
            }
        }
        Ok(())
    }
}

impl Default for RuntimeSupervisor {
    fn default() -> Self {
        Self::new()
    }
}
