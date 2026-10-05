// SPDX-License-Identifier: Apache-2.0
//! OCI image → erofs rootfs conversion pipeline.
//!
//! Phase 7.7.3: Placeholder implementation. The full pipeline will:
//!   1. Pull the OCI image via containerd's content store
//!   2. Unpack layers to a temporary directory
//!   3. Invoke `mkfs.erofs` to build a read-only rootfs image
//!   4. Return the path to the generated `.erofs` file
//!
//! For now, this returns a deterministic placeholder path based on the image
//! name, assuming the erofs image has been pre-built and placed in the
//! image cache directory by an external tool.

use crate::error::AgentError;
use std::path::{Path, PathBuf};

/// Convert an OCI image reference to a local erofs rootfs path.
///
/// In the full implementation, this will pull the image and run `mkfs.erofs`.
/// Currently, it assumes the erofs image already exists at:
///   `{cache_dir}/{sanitized_image_name}.erofs`
pub fn oci_to_erofs(image: &str, cache_dir: &Path) -> Result<PathBuf, AgentError> {
    // Sanitize the image name for use as a filename.
    // Replace '/', ':', and '@' with '_' to avoid path traversal and filesystem issues.
    let sanitized = image.replace(['/', ':', '@'], "_");
    let erofs_path = cache_dir.join(format!("{}.erofs", sanitized));

    // In a real implementation, we would check if the file exists and pull/build if not.
    // For the placeholder, we just return the expected path.
    tracing::debug!(
        image = %image,
        path = %erofs_path.display(),
        "OCI→erofs conversion (placeholder: assuming pre-built)"
    );

    Ok(erofs_path)
}
