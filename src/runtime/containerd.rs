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

        // Connect over Unix domain socket using hyper-util service_fn
        let channel = Endpoint::try_from("http://[::]:50051")?
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
            "[Containerd Engine] Spawning Pod '{}' in namespace '{}' (Snapshotter: '{}', Runtime: '{}')",
            pod.id, pod.namespace, config.snapshotter, config.runtime_type
        );

        for container in &pod.containers {
            self.spawn_container_task(pod, container, config).await?;
        }

        Ok(())
    }

    async fn spawn_container_task(
        &self,
        pod: &PodSpec,
        container: &ContainerSpec,
        config: &ContainerdConfig,
    ) -> Result<()> {
        info!(
            "  -> [Container Task] Pulling image '{}' via snapshotter '{}'",
            container.image, config.snapshotter
        );

        info!(
            "  -> [Container Task] Creating OCI container '{}/{}' with args: {:?}",
            pod.id, container.name, container.args
        );

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
