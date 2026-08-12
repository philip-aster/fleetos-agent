use anyhow::{Context, Result};
use std::path::PathBuf;
use tracing::{info, warn};

pub struct VirtioFsManager {
    base_export_dir: PathBuf,
}

impl VirtioFsManager {
    pub fn new(base_export_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_export_dir: base_export_dir.into(),
        }
    }

    /// Prepares a shared directory structure on the host for virtio-fs export into a Pod VM
    pub async fn prepare_pod_export(&self, pod_id: &str, volume_name: &str) -> Result<PathBuf> {
        let export_path = self.base_export_dir.join(pod_id).join(volume_name);
        if !export_path.exists() {
            tokio::fs::create_dir_all(&export_path)
                .await
                .with_context(|| {
                    format!(
                        "Failed to create virtio-fs export directory: {:?}",
                        export_path
                    )
                })?;
            info!(
                "Created virtio-fs export directory for Pod '{}': {:?}",
                pod_id, export_path
            );
        }
        Ok(export_path)
    }

    /// Derives the socket path for virtiofsd vhost-user daemon communications
    pub fn get_socket_path(&self, pod_id: &str, volume_name: &str) -> PathBuf {
        PathBuf::from(format!(
            "/run/fleetos/virtiofsd-{}-{}.sock",
            pod_id, volume_name
        ))
    }

    /// Cleans up shared host export directory when a Pod is terminated
    pub async fn cleanup_pod_exports(&self, pod_id: &str) -> Result<()> {
        let pod_export_dir = self.base_export_dir.join(pod_id);
        if pod_export_dir.exists() {
            if let Err(e) = tokio::fs::remove_dir_all(&pod_export_dir).await {
                warn!(
                    "Failed to clean up virtio-fs export dir for Pod '{}': {:?}",
                    pod_id, e
                );
            } else {
                info!("Cleaned up virtio-fs export dir for Pod '{}'", pod_id);
            }
        }
        Ok(())
    }
}

impl Default for VirtioFsManager {
    fn default() -> Self {
        Self::new("/var/lib/fleetos/volumes")
    }
}
