use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::{error, info};

pub struct VsockProxy {
    socket_path: String,
}

impl VsockProxy {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// Listens on the host Unix socket created by CloudHypervisor for VSOCK communication
    pub async fn run(&self) -> Result<()> {
        let _ = std::fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path).with_context(|| {
            format!(
                "Failed to bind VSOCK host proxy listener at {}",
                self.socket_path
            )
        })?;

        info!(
            "VSOCK Proxy listener running on socket {}",
            self.socket_path
        );

        loop {
            match listener.accept().await {
                Ok((mut stream, _)) => {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        match stream.read(&mut buf).await {
                            Ok(n) if n > 0 => {
                                info!("VSOCK Proxy received guest request: {} bytes", n);
                                // In production: Resolve identity or secret and echo back to guest
                                let _ = stream.write_all(b"FLEETOS_VSOCK_ACK").await;
                            }
                            _ => {}
                        }
                    });
                }
                Err(e) => {
                    error!("VSOCK accept error: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
