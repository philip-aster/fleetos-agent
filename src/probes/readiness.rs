use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

pub struct ReadinessProbe;

impl ReadinessProbe {
    /// Verifies if a container HTTP/TCP endpoint is ready to receive traffic
    pub async fn check_http(addr: SocketAddr, path: &str, timeout_dur: Duration) -> Result<bool> {
        let res = timeout(timeout_dur, async {
            let mut stream = TcpStream::connect(addr)
                .await
                .context("Failed to connect to readiness target")?;

            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path,
                addr.ip()
            );

            stream.write_all(request.as_bytes()).await?;

            let mut response_buf = [0u8; 512];
            let bytes_read = stream.read(&mut response_buf).await?;

            if bytes_read > 0 {
                let response_text = String::from_utf8_lossy(&response_buf[..bytes_read]);
                let is_ok =
                    response_text.contains("200 OK") || response_text.contains("HTTP/1.1 2");
                return Ok::<bool, anyhow::Error>(is_ok);
            }

            Ok::<bool, anyhow::Error>(false)
        })
        .await;

        match res {
            Ok(Ok(ready)) => Ok(ready),
            Ok(Err(e)) => {
                info!("Readiness probe check failed for {}: {}", addr, e);
                Ok(false)
            }
            Err(_) => {
                info!("Readiness probe timed out for {}", addr);
                Ok(false)
            }
        }
    }
}
