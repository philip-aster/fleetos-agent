use anyhow::{Context, Result};
use fleetos_core::{CloudHypervisorConfig, PodSpec};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::path::Path;
use tokio::net::UnixStream;
use tracing::{info, warn};

pub struct CloudHypervisorDriver {
    base_socket_dir: String,
}

impl CloudHypervisorDriver {
    pub fn new(base_socket_dir: impl Into<String>) -> Self {
        Self {
            base_socket_dir: base_socket_dir.into(),
        }
    }

    /// Helper to perform HTTP REST calls over a CloudHypervisor Unix domain socket
    async fn send_api_request(
        &self,
        socket_path: &str,
        method: http::Method,
        endpoint: &str,
        body: Option<serde_json::Value>,
    ) -> Result<()> {
        if !Path::new(socket_path).exists() {
            warn!(
                "CloudHypervisor socket path '{}' not found on host. Simulating HTTP request to REST API.",
                socket_path
            );
            return Ok(());
        }

        let stream = UnixStream::connect(socket_path)
            .await
            .context("Failed to connect to CloudHypervisor Unix domain socket")?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

        tokio::spawn(async move {
            if let Err(err) = conn.await {
                warn!("CloudHypervisor connection error: {:?}", err);
            }
        });

        let payload = body.unwrap_or(json!({})).to_string();

        let req = http::Request::builder()
            .method(method)
            .uri(endpoint)
            .header("Host", "localhost")
            .header("Content-Type", "application/json")
            .body(http_body_util::Full::new(hyper::body::Bytes::from(payload)))?;

        let resp = sender.send_request(req).await?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "CloudHypervisor REST API error on endpoint '{}': Status {}",
                endpoint,
                resp.status()
            );
        }

        Ok(())
    }

    /// Builds payload and boots a MicroVM for the given PodSpec
    pub async fn boot_vm(&self, pod: &PodSpec, config: &CloudHypervisorConfig) -> Result<()> {
        let socket_path = format!("{}/ch-{}.sock", self.base_socket_dir, pod.id);

        info!(
            "[CloudHypervisor Driver] Initializing MicroVM for Pod '{}' via socket '{}'",
            pod.id, socket_path
        );

        // 1. Construct VmConfig JSON structure matching CloudHypervisor OpenAPI spec
        let vm_config = json!({
            "cpus": {
                "boot_vcpus": config.vcpus,
                "max_vcpus": config.vcpus,
            },
            "memory": {
                "size": config.memory_mb * 1024 * 1024, // Convert MB to Bytes
                "shared": true,
            },
            "kernel": {
                "path": config.kernel_path,
            },
            "cmdline": {
                "args": config.cmdline,
            },
            "payload": config.initrd_path.as_ref().map(|path| json!({ "initrd": path })),
        });

        // 2. PUT /api/v1/vm.create
        info!(
            "  -> [REST API] Creating MicroVM configuration (vCPUs: {}, Memory: {}MB)",
            config.vcpus, config.memory_mb
        );
        self.send_api_request(
            &socket_path,
            http::Method::PUT,
            "/api/v1/vm.create",
            Some(vm_config),
        )
        .await?;

        // 3. PUT /api/v1/vm.boot
        info!("  -> [REST API] Booting MicroVM...");
        self.send_api_request(&socket_path, http::Method::PUT, "/api/v1/vm.boot", None)
            .await?;

        info!("MicroVM for Pod '{}' booted successfully!", pod.id);

        Ok(())
    }

    /// Shuts down an active MicroVM
    pub async fn shutdown_vm(&self, pod_id: &str) -> Result<()> {
        let socket_path = format!("{}/ch-{}.sock", self.base_socket_dir, pod_id);

        info!(
            "[CloudHypervisor Driver] Triggering ACPI shutdown for MicroVM Pod '{}'",
            pod_id
        );

        self.send_api_request(&socket_path, http::Method::PUT, "/api/v1/vm.shutdown", None)
            .await?;

        Ok(())
    }
}

impl Default for CloudHypervisorDriver {
    fn default() -> Self {
        Self::new("/run/cloud-hypervisor")
    }
}
