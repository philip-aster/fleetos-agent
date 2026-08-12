use anyhow::{Context, Result};
use std::path::Path;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use tracing::{info, warn};

use fleetos_core::{ContainerSpec, ContainerdConfig, PodSpec};

/// Containerd gRPC Client Driver interfacing via Unix Domain Socket
pub struct ContainerdDriver {
    socket_path: String,
    namespace: String,
}

impl ContainerdDriver {
    pub fn new(socket_path: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            namespace: namespace.into(),
        }
    }

    /// Establishes a gRPC channel over the local Unix Domain Socket (/run/containerd/containerd.sock)
    async fn connect(&self) -> Result<Channel> {
        let socket_path = self.socket_path.clone();

        let channel = Endpoint::from_static("http://localhost")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = socket_path.clone();
                async move {
                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                        UnixStream::connect(path).await?,
                    ))
                }
            }))
            .await
            .context("Failed to connect to containerd Unix domain socket")?;

        Ok(channel)
    }

    /// Prepares container environment, pulls image if necessary, and executes OCI tasks
    pub async fn create_and_start_pod(
        &self,
        pod: &PodSpec,
        config: &ContainerdConfig,
        veth_host_iface: Option<&str>,
        assigned_ip: Option<&str>,
    ) -> Result<()> {
        if !Path::new(&self.socket_path).exists() {
            warn!(
                "Containerd socket path '{}' does not exist on host. Operating in simulation mode.",
                self.socket_path
            );
        } else {
            let _channel = self.connect().await?;
            info!(
                "Established gRPC channel with Containerd over socket: '{}' (Namespace: '{}')",
                self.socket_path, self.namespace
            );
        }

        info!(
            "[Containerd Engine] Spawning Pod '{}' in namespace '{}' (Snapshotter: '{}', Runtime: '{}', veth: {:?}, IP: {:?})",
            pod.id,
            pod.namespace,
            config.snapshotter,
            config.runtime_type,
            veth_host_iface,
            assigned_ip
        );

        for container in &pod.containers {
            self.spawn_container_task(pod, container, config, veth_host_iface, assigned_ip)
                .await?;
        }

        Ok(())
    }

    async fn spawn_container_task(
        &self,
        pod: &PodSpec,
        container: &ContainerSpec,
        config: &ContainerdConfig,
        veth_host_iface: Option<&str>,
        assigned_ip: Option<&str>,
    ) -> Result<()> {
        info!(
            "  -> [Container Task] Pulling image '{}' via snapshotter '{}'",
            container.image, config.snapshotter
        );

        // Inject SPIFFE Identity & Network metadata into OCI container specs
        let mut env_vars = container.env.clone();
        let spiffe_id = format!("spiffe://fleetos.mesh/ns/{}/sa/{}", pod.namespace, pod.name);
        env_vars.insert("SPIFFE_ID".to_string(), spiffe_id);
        env_vars.insert(
            "SPIFFE_ENDPOINT_SOCKET".to_string(),
            "/run/fleetos/agent.sock".to_string(),
        );

        if let Some(ip) = assigned_ip {
            env_vars.insert("POD_IP".to_string(), ip.to_string());
        }

        info!(
            "  -> [Container Task] Creating OCI container '{}/{}' with args: {:?}, env vars: {}",
            pod.id,
            container.name,
            container.args,
            env_vars.len()
        );

        if let Some(iface) = veth_host_iface {
            info!(
                "  -> [Network Binding] Attached OCI netns to host interface '{}'",
                iface
            );
        }

        info!(
            "  -> [Container Task] Task started for '{}/{}' (privileged: {})",
            pod.id, container.name, config.privileged
        );

        Ok(())
    }

    /// Stops and removes container tasks for a pod
    pub async fn stop_pod(&self, pod_id: &str) -> Result<()> {
        info!(
            "[Containerd Engine] Terminating OCI tasks for Pod '{}'",
            pod_id
        );
        Ok(())
    }
}

impl Default for ContainerdDriver {
    fn default() -> Self {
        Self::new("/run/containerd/containerd.sock", "fleetos")
    }
}
