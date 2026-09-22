// SPDX-License-Identifier: Apache-2.0
//! Host-measured boot: BLAKE3 hash of boot artifacts.
//!
//! Before launching a Cloud Hypervisor MicroVM, the agent measures:
//!   - The kernel image
//!   - The erofs rootfs
//!   - The `fleetos-guest-init` binary
//!
//! The combined BLAKE3 hash is stored and used by host-measured verification
//! to confirm the guest is running expected boot artifacts.
//!
//! This is the pre-launch measurement step. The actual measurement is done
//! by the workload launcher (Batch 10) before bringing up the VM's network.

use std::path::Path;

use crate::error::AgentError;

/// A boot measurement for a MicroVM.
///
/// Computed before launch. Stored by CID. Used by host-measured verification.
#[derive(Debug, Clone)]
pub struct BootMeasurement {
    /// BLAKE3 hash of the kernel image.
    pub kernel_hash: [u8; 32],
    /// BLAKE3 hash of the erofs rootfs.
    pub rootfs_hash: [u8; 32],
    /// BLAKE3 hash of the fleetos-guest-init binary.
    pub guest_init_hash: [u8; 32],
    /// Combined BLAKE3 hash of all three artifacts.
    /// This is what the guest must include in its quote.
    pub combined_hash: [u8; 32],
}

/// Compute the boot measurement for a set of boot artifacts.
///
/// Called by the workload launcher before bringing up the MicroVM's network.
/// All three artifacts must exist and be readable.
pub fn compute_boot_measurement(
    kernel_path: &Path,
    rootfs_path: &Path,
    guest_init_path: &Path,
) -> Result<BootMeasurement, AgentError> {
    let kernel_hash = hash_file(kernel_path)?;
    let rootfs_hash = hash_file(rootfs_path)?;
    let guest_init_hash = hash_file(guest_init_path)?;

    // Combined hash: BLAKE3(kernel_hash || rootfs_hash || guest_init_hash)
    let mut hasher = blake3::Hasher::new();
    hasher.update(&kernel_hash);
    hasher.update(&rootfs_hash);
    hasher.update(&guest_init_hash);
    let combined_hash: [u8; 32] = *hasher.finalize().as_bytes();

    tracing::info!(
        kernel = %kernel_path.display(),
        rootfs = %rootfs_path.display(),
        guest_init = %guest_init_path.display(),
        combined_hash = %hex::encode(combined_hash),
        "boot measurement computed"
    );

    Ok(BootMeasurement {
        kernel_hash,
        rootfs_hash,
        guest_init_hash,
        combined_hash,
    })
}

/// Hash a file with BLAKE3.
fn hash_file(path: &Path) -> Result<[u8; 32], AgentError> {
    let data = std::fs::read(path).map_err(|e| {
        AgentError::Internal(format!(
            "failed to read boot artifact {}: {}",
            path.display(),
            e
        ))
    })?;

    Ok(*blake3::hash(&data).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_measurement_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.erofs");
        let guest_init = dir.path().join("fleetos-guest-init");

        std::fs::write(&kernel, b"kernel-data").unwrap();
        std::fs::write(&rootfs, b"rootfs-data").unwrap();
        std::fs::write(&guest_init, b"guest-init-data").unwrap();

        let m1 = compute_boot_measurement(&kernel, &rootfs, &guest_init).unwrap();
        let m2 = compute_boot_measurement(&kernel, &rootfs, &guest_init).unwrap();

        assert_eq!(m1.combined_hash, m2.combined_hash);
    }

    #[test]
    fn boot_measurement_changes_with_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.erofs");
        let guest_init = dir.path().join("fleetos-guest-init");

        std::fs::write(&kernel, b"kernel-v1").unwrap();
        std::fs::write(&rootfs, b"rootfs-data").unwrap();
        std::fs::write(&guest_init, b"guest-init-data").unwrap();

        let m1 = compute_boot_measurement(&kernel, &rootfs, &guest_init).unwrap();

        // Change the kernel.
        std::fs::write(&kernel, b"kernel-v2").unwrap();
        let m2 = compute_boot_measurement(&kernel, &rootfs, &guest_init).unwrap();

        assert_ne!(m1.combined_hash, m2.combined_hash);
    }

    #[test]
    fn missing_artifact_fails() {
        let dir = tempfile::tempdir().unwrap();
        let kernel = dir.path().join("vmlinux");
        let rootfs = dir.path().join("rootfs.erofs");
        let guest_init = dir.path().join("fleetos-guest-init");

        std::fs::write(&kernel, b"kernel-data").unwrap();
        std::fs::write(&rootfs, b"rootfs-data").unwrap();
        // guest_init is missing.

        let result = compute_boot_measurement(&kernel, &rootfs, &guest_init);
        assert!(result.is_err());
    }
}
