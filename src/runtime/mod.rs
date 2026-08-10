pub mod cloud_hypervisor;
pub mod containerd;

use cloud_hypervisor::CloudHypervisorDriver;
use containerd::ContainerdDriver;
use fleetos_core::{PodSpec, RuntimeEngine};
use tracing::info;

pub struct RuntimeDriver {
    containerd: ContainerdDriver,
    cloud_hypervisor: CloudHypervisorDriver,
}

impl RuntimeDriver {
    pub fn new() -> Self {
        Self {
            containerd: ContainerdDriver::default(),
            cloud_hypervisor: CloudHypervisorDriver::default(),
        }
    }

    /// Spawns the workload according to the specified RuntimeEngine
    pub async fn spawn_pod(&self, pod: &PodSpec) -> Result<(), String> {
        match &pod.runtime {
            RuntimeEngine::CloudHypervisor(cfg) => {
                info!(
                    "[CloudHypervisor] Booting MicroVM for Pod '{}' (Kernel: '{}', vCPUs: {}, Memory: {}MB)",
                    pod.id, cfg.kernel_path, cfg.vcpus, cfg.memory_mb
                );
                self.cloud_hypervisor.boot_vm(pod, cfg).await.map_err(|e| {
                    format!("CloudHypervisor boot failed for pod '{}': {}", pod.id, e)
                })?;
                Ok(())
            }
            RuntimeEngine::Containerd(cfg) => {
                info!(
                    "[Containerd] Spawning OCI pod '{}' (Containers: {}, Snapshotter: '{}')",
                    pod.id,
                    pod.containers.len(),
                    cfg.snapshotter
                );
                self.containerd
                    .create_and_start_pod(pod, cfg)
                    .await
                    .map_err(|e| {
                        format!("Containerd execution failed for pod '{}': {}", pod.id, e)
                    })?;
                Ok(())
            }
        }
    }

    /// Terminates an active workload
    pub async fn stop_pod(&self, pod_id: &str) -> Result<(), String> {
        info!("Terminating workload for Pod '{}'", pod_id);

        let containerd_res = self.containerd.stop_pod(pod_id).await;
        let ch_res = self.cloud_hypervisor.shutdown_vm(pod_id).await;

        if let Err(e) = containerd_res {
            tracing::warn!("Containerd stop error for pod '{}': {}", pod_id, e);
        }
        if let Err(e) = ch_res {
            tracing::warn!("CloudHypervisor shutdown error for pod '{}': {}", pod_id, e);
        }

        Ok(())
    }
}

impl Default for RuntimeDriver {
    fn default() -> Self {
        Self::new()
    }
}
