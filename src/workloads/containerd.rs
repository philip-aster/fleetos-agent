// SPDX-License-Identifier: Apache-2.0
//! containerd runtime adapter.
//!
//! Drives containerd through the `containerd-client` gRPC SDK (lower-level
//! containers/tasks/content services — NOT CRI). No CLI shelling.
//!
//! boot: build OCI spec from PodSpec → create container → create+start task.
//! stop: kill (SIGTERM) → grace wait → force SIGKILL → delete task+container.

use std::time::Duration;

use serde_json::json;

use super::WorkloadSpec;
use super::volumes::PreparedMount;
use crate::error::AgentError;

/// Default containerd socket.
pub const CONTAINERD_SOCKET: &str = "unix:///run/containerd/containerd.sock";

/// The adapter holds a gRPC channel to containerd.
pub struct ContainerdAdapter {
    namespace: String,
    hosts_content: std::sync::RwLock<String>,
    channel: tokio::sync::Mutex<Option<tonic::transport::Channel>>,
}

impl ContainerdAdapter {
    /// Create without connecting. Connection happens lazily on first use.
    pub fn new_lazy(namespace: &str, hosts_content: String) -> Self {
        Self {
            namespace: namespace.to_string(),
            hosts_content: std::sync::RwLock::new(hosts_content),
            channel: tokio::sync::Mutex::new(None),
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Update the agent-rendered /etc/hosts content (driven by WatchRoutes).
    pub fn set_hosts_content(&self, content: String) {
        *self.hosts_content.write().unwrap() = content;
    }

    /// Lazily establish (or reuse) the gRPC channel to containerd.
    async fn channel(&self) -> Result<tonic::transport::Channel, AgentError> {
        let mut guard = self.channel.lock().await;
        if guard.is_none() {
            let ch = tonic::transport::Endpoint::try_from(CONTAINERD_SOCKET)
                .map_err(|e| AgentError::Workload(format!("containerd endpoint: {e}")))?
                .connect()
                .await
                .map_err(|e| AgentError::Workload(format!("containerd connect: {e}")))?;
            *guard = Some(ch);
        }
        Ok(guard.clone().unwrap())
    }

    /// Boot a container. Returns the task PID.
    pub async fn boot(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
    ) -> Result<u32, AgentError> {
        let pod_spec = spec
            .pod_spec
            .as_ref()
            .ok_or_else(|| AgentError::Workload("containerd boot requires full PodSpec".into()))?;

        let pod_id = pod_spec
            .pod_id
            .clone()
            .unwrap_or_else(|| spec.workload_id.clone());

        // Q3: Agent renders /etc/hosts for the containerd path.
        let hosts_path = format!("/run/fleetos/pods/{}/hosts", spec.workload_id);
        if let Some(parent) = std::path::Path::new(&hosts_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let hosts_content = self.hosts_content.read().unwrap().clone();
        std::fs::write(&hosts_path, &hosts_content)?;

        let channel = self.channel().await?;
        let mut containers = ContainersClient::new(channel.clone());
        let mut tasks = TasksClient::new(channel.clone());

        // 1. OCI spec (includes /etc/hosts bind-mount + cgroup limits).
        let oci_spec = self.build_oci_spec(spec, mounts)?;

        // 2. Create container + task via the containerd SDK.
        //    SDK VERIFICATION POINT: containers/tasks service request shapes.
        use containerd_client::services::v1::containers_client::ContainersClient;
        use containerd_client::services::v1::tasks_client::TasksClient;
        use containerd_client::services::v1::{
            Container, CreateContainerRequest, CreateTaskRequest, StartRequest,
        };

        let container = Container {
            id: pod_id.clone(),
            image: spec.image.clone(),
            // The OCI spec is packed into the container spec as a protobuf Any.
            spec: Some(oci_spec),
            snapshotter: "erofs".to_string(), // erofs snapshotter (read-only rootfs)
            ..Default::default()
        };

        containers
            .create(CreateContainerRequest {
                container: Some(container),
            })
            .await
            .map_err(|e| AgentError::Workload(format!("containerd create container: {e}")))?;

        let created = tasks
            .create(CreateTaskRequest {
                container_id: pod_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| AgentError::Workload(format!("containerd create task: {e}")))?;

        let pid = created.into_inner().pid;

        tasks
            .start(StartRequest {
                container_id: pod_id.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| AgentError::Workload(format!("containerd start task: {e}")))?;

        tracing::info!(pod_id, pid, "containerd container booted");
        Ok(pid)
    }

    /// Stop a container: SIGTERM → grace wait → SIGKILL → delete.
    pub async fn stop(&self, pod_id: &str, grace_period_secs: u64) -> Result<(), AgentError> {
        // SDK VERIFICATION POINT: tasks Kill/Delete, containers Delete.
        use containerd_client::services::v1::containers_client::ContainersClient;
        use containerd_client::services::v1::tasks_client::TasksClient;
        use containerd_client::services::v1::{
            DeleteContainerRequest, DeleteTaskRequest, KillRequest,
        };

        let channel = self.channel().await?;
        let mut tasks = TasksClient::new(channel.clone());
        let mut containers = ContainersClient::new(channel.clone());

        // SIGTERM (signal 15).
        let _ = tasks
            .kill(KillRequest {
                container_id: pod_id.to_string(),
                signal: 15,
                ..Default::default()
            })
            .await;

        tokio::time::sleep(Duration::from_secs(grace_period_secs)).await;

        // Force SIGKILL (signal 9) if still alive.
        let _ = tasks
            .kill(KillRequest {
                container_id: pod_id.to_string(),
                signal: 9,
                ..Default::default()
            })
            .await;

        let _ = tasks
            .delete(DeleteTaskRequest {
                container_id: pod_id.to_string(),
                ..Default::default()
            })
            .await;

        let _ = containers
            .delete(DeleteContainerRequest {
                id: pod_id.to_string(),
            })
            .await;

        tracing::info!(pod_id, "containerd container stopped");
        Ok(())
    }

    /// Build the OCI runtime spec (config.json) as a protobuf Any.
    ///
    /// Includes /etc/hosts bind-mount (Q3: agent renders hosts for the
    /// containerd path) and cgroup limits from PodSpec.resources.
    fn build_oci_spec(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
    ) -> Result<::prost_types::Any, AgentError> {
        let pod_spec = spec.pod_spec.as_ref().unwrap();

        // /etc/hosts bind-mount source (agent-managed file path).
        let hosts_path = format!("/run/fleetos/pods/{}/hosts", spec.workload_id);

        let mut oci_mounts = vec![
            json!({
                "destination": "/etc/hosts",
                "type": "bind",
                "source": hosts_path,
                "options": ["rbind", "ro"]
            }),
            json!({
                "destination": "/proc",
                "type": "proc",
                "source": "proc"
            }),
        ];

        // User-declared volume mounts.
        for m in mounts {
            oci_mounts.push(json!({
                "destination": m.mount_path,
                "type": "bind",
                "source": m.host_path.to_string_lossy(),
                "options": if m.read_only { ["rbind", "ro"] } else { ["rbind", "rw"] },
            }));
        }

        // cgroup limits from PodSpec.resources.
        let (cpu_limit, mem_limit) = match pod_spec.resources.as_ref() {
            Some(r) => (r.vcpus as u64, (r.memory_mb as u64) * 1024 * 1024),
            None => (1, 512 * 1024 * 1024),
        };

        let env: Vec<String> = pod_spec
            .env
            .iter()
            .map(|e| format!("{}={}", e.name, e.value))
            .collect();

        let oci = json!({
            "ociVersion": "1.0.2",
            "process": {
                "user": { "uid": 0, "gid": 0 },
                "args": ["/init"],
                "env": env,
                "cwd": "/",
            },
            "root": { "path": "rootfs", "readonly": true },
            "hostname": spec.hostname,
            "mounts": oci_mounts,
            "linux": {
                "namespaces": [
                    {"type": "pid"}, {"type": "ipc"}, {"type": "uts"},
                    {"type": "mount"}, {"type": "network"}
                ],
                "resources": {
                    "cpu": { "quota": cpu_limit * 100_000, "period": 100_000 },
                    "memory": { "limit": mem_limit }
                }
            }
        });

        // Pack the OCI JSON into a protobuf Any under the OCI spec type URL.
        let spec_bytes = serde_json::to_vec(&oci).map_err(|e| {
            AgentError::Workload(format!("OCI spec JSON serialization failed: {}", e))
        })?;
        Ok(::prost_types::Any {
            type_url: "types.containerd.io/opencontainers/runtime-spec/1/Spec".to_string(),
            value: spec_bytes,
        })
    }
}
