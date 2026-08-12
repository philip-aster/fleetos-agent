pub mod proxy;

pub use proxy::VsockProxy;

use anyhow::Result;
use std::path::PathBuf;
use tokio::sync::broadcast;
use tracing::info;

pub struct VsockManager {
    base_socket_dir: PathBuf,
}

impl VsockManager {
    pub fn new(base_socket_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_socket_dir: base_socket_dir.into(),
        }
    }

    /// Generates standard VSOCK Unix socket path for a Pod VM
    pub fn get_pod_vsock_path(&self, pod_id: &str) -> PathBuf {
        self.base_socket_dir.join(format!("{}.vsock", pod_id))
    }

    /// Spawns a background VSOCK proxy listener for a Cloud Hypervisor MicroVM Pod
    pub fn spawn_pod_proxy(
        &self,
        pod_id: &str,
        spire_socket: Option<&str>,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let socket_path = self.get_pod_vsock_path(pod_id);
        let mut proxy = VsockProxy::new(socket_path.to_string_lossy());

        if let Some(target) = spire_socket {
            proxy = proxy.with_target_socket(target);
        }

        info!("Spawning VSOCK host proxy worker for Pod '{}'", pod_id);

        let pod_id_owned = pod_id.to_owned();

        tokio::spawn(async move {
            if let Err(e) = proxy.run(shutdown_rx).await {
                tracing::error!(
                    "VSOCK proxy worker failed for Pod '{}': {:?}",
                    pod_id_owned,
                    e
                );
            }
        });

        Ok(())
    }
}

impl Default for VsockManager {
    fn default() -> Self {
        Self::new("/run/fleetos/vsock")
    }
}
