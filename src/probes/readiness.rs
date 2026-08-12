use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tokio_vsock::{VsockAddr, VsockStream};
use tracing::info;

pub struct ReadinessProbe;

impl ReadinessProbe {
    /// Verifies if a container or MicroVM HTTP endpoint is ready to receive traffic (2xx range match)
    pub async fn check_http(addr: SocketAddr, path: &str, timeout_dur: Duration) -> Result<bool> {
        let url = format!("http://{}{}", addr, path);
        let client = reqwest::Client::builder().timeout(timeout_dur).build()?;

        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => Ok(true),
            Ok(resp) => {
                info!(
                    "Readiness probe returned non-success status {} for {}",
                    resp.status(),
                    url
                );
                Ok(false)
            }
            Err(e) => {
                info!("Readiness probe HTTP request failed for {}: {}", url, e);
                Ok(false)
            }
        }
    }

    /// Verifies guest application readiness over a Cloud Hypervisor VSOCK channel
    pub async fn check_vsock(cid: u32, port: u32, timeout_dur: Duration) -> Result<bool> {
        let addr = VsockAddr::new(cid, port);
        let res = timeout(timeout_dur, async {
            let mut stream = VsockStream::connect(addr)
                .await
                .context("Failed to connect to VSOCK readiness port")?;

            // Write readiness ping byte sequence
            stream.write_all(b"READY?\n").await?;

            let mut response_buf = [0u8; 64];
            let bytes_read = stream.read(&mut response_buf).await?;

            if bytes_read > 0 {
                let response_text = String::from_utf8_lossy(&response_buf[..bytes_read]);
                return Ok::<bool, anyhow::Error>(response_text.trim() == "OK");
            }

            Ok::<bool, anyhow::Error>(false)
        })
        .await;

        match res {
            Ok(Ok(ready)) => Ok(ready),
            Ok(Err(e)) => {
                info!(
                    "VSOCK readiness probe failed for CID {}:port {}: {}",
                    cid, port, e
                );
                Ok(false)
            }
            Err(_) => {
                info!(
                    "VSOCK readiness probe timed out for CID {}:port {}",
                    cid, port
                );
                Ok(false)
            }
        }
    }
}
