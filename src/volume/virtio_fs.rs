use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use tracing::info;

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
    pub fn prepare_pod_export(&self, pod_id: &str, volume_name: &str) -> Result<PathBuf> {
        let export_path = self.base_export_dir.join(pod_id).join(volume_name);
        if !export_path.exists() {
            fs::create_dir_all(&export_path).with_context(|| {
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
}
