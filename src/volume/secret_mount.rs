use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct SecretMountManager;

impl SecretMountManager {
    /// Writes decrypted secrets directly into a RAM-backed tmpfs mount point
    pub fn write_decrypted_secret(
        mount_dir: &Path,
        secret_filename: &str,
        secret_bytes: &[u8],
    ) -> Result<PathBuf> {
        if !mount_dir.exists() {
            fs::create_dir_all(mount_dir)
                .with_context(|| format!("Failed to create secret directory {:?}", mount_dir))?;
        }

        let secret_file_path = mount_dir.join(secret_filename);
        fs::write(&secret_file_path, secret_bytes).with_context(|| {
            format!("Failed to write decrypted secret to {:?}", secret_file_path)
        })?;

        info!(
            "Decrypted secret successfully written to secure RAM mount: {:?}",
            secret_file_path
        );
        Ok(secret_file_path)
    }
}
