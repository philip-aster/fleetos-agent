use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::warn;

pub struct LivenessProbe;

impl LivenessProbe {
    /// Checks TCP socket connectivity to a workload inside a MicroVM or OCI container
    pub async fn check_tcp(addr: SocketAddr, timeout_dur: Duration) -> Result<bool> {
        match timeout(timeout_dur, TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => Ok(true),
            Ok(Err(e)) => {
                warn!("TCP Liveness probe failed for {}: {}", addr, e);
                Ok(false)
            }
            Err(_) => {
                warn!("TCP Liveness probe timed out for {}", addr);
                Ok(false)
            }
        }
    }

    /// Checks HTTP health endpoint connectivity (e.g. GET /healthz)
    pub async fn check_http(url: &str, timeout_dur: Duration) -> Result<bool> {
        let client = reqwest::Client::builder().timeout(timeout_dur).build()?;

        match client.get(url).send().await {
            Ok(resp) if resp.status().is_success() => Ok(true),
            Ok(resp) => {
                warn!(
                    "HTTP Liveness probe returned status {} for {}",
                    resp.status(),
                    url
                );
                Ok(false)
            }
            Err(e) => {
                warn!("HTTP Liveness probe failed for {}: {}", url, e);
                Ok(false)
            }
        }
    }

    /// Checks VSOCK socket connectivity to guest agent inside a Cloud Hypervisor MicroVM
    pub async fn check_vsock(cid: u32, port: u32, timeout_dur: Duration) -> Result<bool> {
        let addr = VsockAddr::new(cid, port);
        match timeout(timeout_dur, VsockStream::connect(addr)).await {
            Ok(Ok(_stream)) => Ok(true),
            Ok(Err(e)) => {
                warn!(
                    "VSOCK Liveness probe failed for CID {}:port {}: {}",
                    cid, port, e
                );
                Ok(false)
            }
            Err(_) => {
                warn!(
                    "VSOCK Liveness probe timed out for CID {}:port {}",
                    cid, port
                );
                Ok(false)
            }
        }
    }
}
