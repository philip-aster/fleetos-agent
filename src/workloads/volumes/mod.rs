// SPDX-License-Identifier: Apache-2.0
//! Volume management.
//!
//! Volumes are defined in workload.proto. Supported sources:
//! - EmptyDir: per-pod scratch
//! - HostPath: host path mount (security-gated)
//! - Persistent: persistent volume (deferred)

use fleetos_core::proto::fleetos::Volume;
use fleetos_core::proto::workload::VolumeMount;

/// A prepared volume mount.
#[derive(Debug, Clone)]
pub struct PreparedMount {
    pub name: String,
    pub mount_path: String,
    pub read_only: bool,
    pub source: VolumeSource,
}

/// Volume source.
#[derive(Debug, Clone)]
pub enum VolumeSource {
    /// Per-pod scratch directory.
    EmptyDir { size_limit_bytes: Option<u64> },
    /// Host path mount.
    HostPath { path: String, host_path_type: i32 },
    // Persistent volume is deferred (schema comment in workload.proto).
    // Add it additively with a fresh oneof field number when it lands.
}

/// Prepare volume mounts from proto definitions.
pub fn prepare_mounts(volumes: &[Volume], mounts: &[VolumeMount]) -> Vec<PreparedMount> {
    let mut prepared = Vec::new();

    for mount in mounts {
        // Find the volume by name.
        let volume = volumes.iter().find(|v| v.name == mount.name);

        let source = match volume.and_then(|v| v.source.as_ref()) {
            Some(fleetos_core::proto::fleetos::volume::Source::EmptyDir(empty_dir)) => {
                VolumeSource::EmptyDir {
                    size_limit_bytes: empty_dir.size_limit_bytes,
                }
            }
            Some(fleetos_core::proto::fleetos::volume::Source::HostPath(host_path)) => {
                VolumeSource::HostPath {
                    path: host_path.path.clone(),
                    host_path_type: host_path.r#type,
                }
            }
            None => continue, // No source, skip.
        };

        prepared.push(PreparedMount {
            name: mount.name.clone(),
            mount_path: mount.mount_path.clone(),
            read_only: mount.read_only,
            source,
        });
    }

    prepared
}
