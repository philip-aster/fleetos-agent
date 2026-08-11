use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::warn;

pub struct LivenessProbe;

impl LivenessProbe {
    /// Checks TCP socket connectivity to a workload inside a MicroVM
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
}
