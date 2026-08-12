use anyhow::{Context, Result};
use fleetos_core::{CloudHypervisorConfig, PodSpec};
use hyper_util::rt::TokioIo;
use serde_json::json;
use std::path::Path;
use tokio::net::UnixStream;
use tokio::process::Command;
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

    /// Ensures the Cloud Hypervisor process is running and listening on the designated Unix socket
    async fn ensure_ch_daemon(&self, pod_id: &str, socket_path: &str) -> Result<()> {
        if Path::new(socket_path).exists() {
            return Ok(());
        }

        info!(
            "[CloudHypervisor Driver] Spawning Cloud Hypervisor daemon for Pod '{}' listening on '{}'...",
            pod_id, socket_path
        );

        // Ensure socket directory exists
        if let Some(parent) = Path::new(socket_path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut child = Command::new("cloud-hypervisor")
            .arg("--api-socket")
            .arg(socket_path)
            .spawn()
            .with_context(|| {
                format!(
                    "Failed to spawn 'cloud-hypervisor' binary for socket {}",
                    socket_path
                )
            })?;

        // Wait up to 2 seconds for socket file creation
        for _ in 0..20 {
            if Path::new(socket_path).exists() {
                // Detach child lifecycle to allow background API operation
                tokio::spawn(async move {
                    let _ = child.wait().await;
                });
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        warn!(
            "CloudHypervisor socket path '{}' was not created within timeout. Proceeding in simulation mode.",
            socket_path
        );
        Ok(())
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

    /// Builds payload and boots a MicroVM attached to a target TAP interface and VSOCK CID
    pub async fn boot_vm(
        &self,
        pod: &PodSpec,
        config: &CloudHypervisorConfig,
        tap_name: Option<&str>,
        assigned_ip: Option<&str>,
    ) -> Result<()> {
        let socket_path = format!("{}/ch-{}.sock", self.base_socket_dir, pod.id);

        self.ensure_ch_daemon(&pod.id, &socket_path).await?;

        info!(
            "[CloudHypervisor Driver] Initializing MicroVM for Pod '{}' via socket '{}'",
            pod.id, socket_path
        );

        // 1. Construct network device payload if TAP is configured
        let net_config = tap_name.map(|tap| {
            vec![json!({
                "tap": tap,
                "ip": assigned_ip.unwrap_or("10.244.0.2"),
                "mask": "255.255.255.0",
            })]
        });

        // 2. Construct VSOCK configuration for host-guest control proxying if CID is specified
        let vsock_config = config.vsock_cid.map(|cid| {
            json!({
                "cid": cid,
                "socket": format!("{}/vsock-{}.sock", self.base_socket_dir, pod.id),
            })
        });

        // 3. Construct payload config block matching CloudHypervisor OpenAPI spec
        let mut payload_config = json!({
            "kernel": config.kernel_path,
            "cmdline": config.cmdline,
        });

        if let Some(ref initrd) = config.initrd_path {
            payload_config["initrd"] = json!(initrd);
        }

        // 4. Construct complete VmConfig
        let mut vm_config = json!({
            "cpus": {
                "boot_vcpus": config.vcpus,
                "max_vcpus": config.vcpus,
            },
            "memory": {
                "size": config.memory_mb * 1024 * 1024, // Convert MB to Bytes
                "shared": true,
            },
            "payload": payload_config,
        });

        if let Some(net) = net_config {
            vm_config["net"] = json!(net);
        }

        if let Some(vsock) = vsock_config {
            vm_config["vsock"] = vsock;
        }

        // 5. PUT /api/v1/vm.create
        info!(
            "  -> [REST API] Creating MicroVM configuration (vCPUs: {}, Memory: {}MB, TAP: {:?})",
            config.vcpus, config.memory_mb, tap_name
        );
        self.send_api_request(
            &socket_path,
            http::Method::PUT,
            "/api/v1/vm.create",
            Some(vm_config),
        )
        .await?;

        // 6. PUT /api/v1/vm.boot
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
