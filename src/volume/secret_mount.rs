use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

pub struct SecretMountManager;

impl SecretMountManager {
    /// Writes decrypted secrets directly into a RAM-backed tmpfs mount point with restrictive POSIX permissions
    pub async fn write_decrypted_secret(
        mount_dir: &Path,
        secret_filename: &str,
        secret_bytes: &[u8],
    ) -> Result<PathBuf> {
        if !mount_dir.exists() {
            tokio::fs::create_dir_all(mount_dir)
                .await
                .with_context(|| format!("Failed to create secret directory {:?}", mount_dir))?;

            // Set directory permissions to rwx------ (0700)
            tokio::fs::set_permissions(mount_dir, std::fs::Permissions::from_mode(0o700)).await?;
        }

        let secret_file_path = mount_dir.join(secret_filename);

        tokio::fs::write(&secret_file_path, secret_bytes)
            .await
            .with_context(|| {
                format!("Failed to write decrypted secret to {:?}", secret_file_path)
            })?;

        // Set file permissions to rw------- (0600)
        tokio::fs::set_permissions(&secret_file_path, std::fs::Permissions::from_mode(0o600))
            .await?;

        info!(
            "Decrypted secret successfully written to secure RAM mount: {:?}",
            secret_file_path
        );
        Ok(secret_file_path)
    }

    /// Zero-fills and removes a secret file from host RAM/tmpfs storage upon Pod teardown
    pub async fn secure_wipe_secret(secret_file_path: &Path) -> Result<()> {
        if secret_file_path.exists() {
            if let Ok(metadata) = tokio::fs::metadata(secret_file_path).await {
                let len = metadata.len() as usize;
                let zeroes = vec![0u8; len];
                let _ = tokio::fs::write(secret_file_path, &zeroes).await;
            }

            if let Err(e) = tokio::fs::remove_file(secret_file_path).await {
                warn!(
                    "Failed to delete secret file {:?}: {:?}",
                    secret_file_path, e
                );
            } else {
                info!(
                    "Securely wiped and deleted secret file: {:?}",
                    secret_file_path
                );
            }
        }
        Ok(())
    }
}
