pub mod secret_mount;
pub mod virtio_fs;

pub use secret_mount::SecretMountManager;
pub use virtio_fs::VirtioFsManager;

use anyhow::Result;
use fleetos_core::VolumeSpec;
use std::path::PathBuf;

pub struct VolumeManager {
    virtio_fs: VirtioFsManager,
}

impl VolumeManager {
    pub fn new(base_export_dir: impl Into<PathBuf>) -> Self {
        Self {
            virtio_fs: VirtioFsManager::new(base_export_dir),
        }
    }

    /// Prepares storage backends defined in a PodSpec volume list
    pub async fn prepare_pod_volumes(&self, pod_id: &str, volumes: &[VolumeSpec]) -> Result<()> {
        for vol in volumes {
            self.virtio_fs.prepare_pod_export(pod_id, &vol.name).await?;
        }
        Ok(())
    }

    /// Cleans up host volume mounts and exports upon Pod teardown
    pub async fn cleanup_pod_volumes(&self, pod_id: &str) -> Result<()> {
        self.virtio_fs.cleanup_pod_exports(pod_id).await?;
        Ok(())
    }
}

impl Default for VolumeManager {
    fn default() -> Self {
        Self::new("/var/lib/fleetos/volumes")
    }
}
