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

impl RuntimeSupervisor {
    pub fn new() -> Self {
        Self {
            cloud_hypervisor: CloudHypervisorDriver::default(),
            containerd: ContainerdDriver::default(),
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
