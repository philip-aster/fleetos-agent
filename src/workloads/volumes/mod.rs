// SPDX-License-Identifier: Apache-2.0
//! Volume management.
//!
//! Volume sources (workload.proto, CR-CORE-2):
//! - EmptyDir: per-pod scratch. Keyed by pod_id; dies with the POD, not the workload.
//! - HostPath: host path mount. SECURITY-GATED, default-DENY (zero-trust surface).
//! - Persistent: deferred (CR-CORE-2). Not yet representable in the schema oneof.

use std::fs;
use std::path::PathBuf;

use crate::error::AgentError;
use fleetos_core::proto::fleetos::{Volume, volume::Source};
use fleetos_core::proto::workload::VolumeMount;

/// A volume mount resolved to a concrete host-side source path, ready to hand
/// to a runtime adapter.
#[derive(Debug, Clone)]
pub struct PreparedMount {
    pub name: String,
    /// Container/guest-side mount destination.
    pub mount_path: String,
    pub read_only: bool,
    /// Resolved host-side source path.
    pub host_path: PathBuf,
    pub source: VolumeSource,
}

#[derive(Debug, Clone)]
pub enum VolumeSource {
    /// Per-pod scratch directory. Created under a scratch root, keyed by pod_id.
    EmptyDir { size_limit_bytes: Option<u64> },
    /// Host path mount (security-gated).
    HostPath { host_path_type: i32 },
    // Persistent volumes are deferred (CR-CORE-2). Add a fresh oneof variant when they land.
}

/// Configuration for volume preparation.
#[derive(Debug, Clone)]
pub struct VolumeConfig {
    /// Root directory under which EmptyDir scratch volumes are created.
    pub scratch_root: PathBuf,
    /// Whether HostPath mounts are permitted. Default false (fail-closed).
    pub allow_host_path: bool,
}

impl Default for VolumeConfig {
    fn default() -> Self {
        Self {
            scratch_root: PathBuf::from("/var/lib/fleetos/scratch"),
            allow_host_path: false,
        }
    }
}

/// Prepare volume mounts for a single pod.
///
/// - EmptyDir → creates `{scratch_root}/{pod_id}/{volume_name}`. Dies with the pod.
/// - HostPath → rejected unless explicitly enabled (default-DENY); even then the
///   path must exist. Fail-closed.
///
/// Errors (fail-closed) on an undefined volume reference or a missing source.
pub fn prepare_mounts(
    config: &VolumeConfig,
    pod_id: &str,
    volumes: &[Volume],
    mounts: &[VolumeMount],
) -> Result<Vec<PreparedMount>, AgentError> {
    let mut prepared = Vec::with_capacity(mounts.len());

    for mount in mounts {
        let volume = volumes
            .iter()
            .find(|v| v.name == mount.name)
            .ok_or_else(|| {
                AgentError::Workload(format!(
                    "volume mount '{}' references undefined volume",
                    mount.name
                ))
            })?;

        let pm = match volume.source.as_ref() {
            Some(Source::EmptyDir(empty_dir)) => {
                let host_path = config.scratch_root.join(pod_id).join(&volume.name);
                fs::create_dir_all(&host_path)?;
                PreparedMount {
                    name: volume.name.clone(),
                    mount_path: mount.mount_path.clone(),
                    read_only: mount.read_only,
                    host_path,
                    source: VolumeSource::EmptyDir {
                        size_limit_bytes: empty_dir.size_limit_bytes,
                    },
                }
            }
            Some(Source::HostPath(host_path)) => {
                // SECURITY: HostPath is a zero-trust security surface.
                // Default-DENY until an explicit SAG/admin policy enables it.
                if !config.allow_host_path {
                    return Err(AgentError::Workload(format!(
                        "hostPath volume '{}' rejected: HostPath is disabled by default \
                         (zero-trust security surface, CR-CORE-2)",
                        volume.name
                    )));
                }
                let hp = PathBuf::from(&host_path.path);
                if !hp.exists() {
                    return Err(AgentError::Workload(format!(
                        "hostPath volume '{}' rejected: path does not exist: {}",
                        volume.name,
                        hp.display()
                    )));
                }
                PreparedMount {
                    name: volume.name.clone(),
                    mount_path: mount.mount_path.clone(),
                    read_only: mount.read_only,
                    host_path: hp,
                    source: VolumeSource::HostPath {
                        host_path_type: host_path.r#type,
                    },
                }
            }
            None => {
                return Err(AgentError::Workload(format!(
                    "volume '{}' has no source (fail-closed)",
                    volume.name
                )));
            }
        };
        prepared.push(pm);
    }

    Ok(prepared)
}

/// Tear down a pod's EmptyDir scratch directory. Called on pod eviction/death.
pub fn teardown_pod_scratch(config: &VolumeConfig, pod_id: &str) -> Result<(), AgentError> {
    let pod_dir = config.scratch_root.join(pod_id);
    if pod_dir.exists() {
        fs::remove_dir_all(&pod_dir)?;
    }
    Ok(())
}
