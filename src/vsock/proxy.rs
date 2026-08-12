use anyhow::{Context, Result};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub struct VsockProxy {
    socket_path: String,
    target_socket: Option<String>,
}

impl VsockProxy {
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            target_socket: None,
        }
    }

    /// Sets a target Unix socket path (e.g. SPIFFE agent socket) to proxy guest requests to
    pub fn with_target_socket(mut self, target_socket: impl Into<String>) -> Self {
        self.target_socket = Some(target_socket.into());
        self
    }

    /// Listens on the host Unix socket created by CloudHypervisor for VSOCK communication
    pub async fn run(&self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        // Clean up pre-existing socket file if necessary
        let _ = std::fs::remove_file(&self.socket_path);

        let listener = UnixListener::bind(&self.socket_path).with_context(|| {
            format!(
                "Failed to bind VSOCK host proxy listener at {}",
                self.socket_path
            )
        })?;

        // Restrict access permissions to standard daemon user
        let _ = std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600));

        info!(
            "VSOCK Proxy listener running on socket: {}",
            self.socket_path
        );

        loop {
            tokio::select! {
                accept_res = listener.accept() => {
                    match accept_res {
                        Ok((mut client_stream, _)) => {
                            let target_socket = self.target_socket.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(&mut client_stream, target_socket.as_deref()).await {
                                    warn!("Error handling guest VSOCK stream: {:?}", e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("VSOCK accept error: {:?}", e);
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down VSOCK proxy listener at {}", self.socket_path);
                    break;
                }
            }
        }

        // Cleanup on exit
        let _ = std::fs::remove_file(&self.socket_path);
        Ok(())
    }

    async fn handle_connection(
        client_stream: &mut UnixStream,
        target_socket: Option<&str>,
    ) -> Result<()> {
        if let Some(target_path) = target_socket {
            // Forward directly to host target socket (e.g., SPIFFE agent)
            let mut target_stream = UnixStream::connect(target_path).await.with_context(|| {
                format!("Failed to connect to proxy target socket: {}", target_path)
            })?;

            tokio::io::copy_bidirectional(client_stream, &mut target_stream).await?;
        } else {
            // Simple echo / ack mode for health probing
            let mut buf = [0u8; 1024];
            let n = client_stream.read(&mut buf).await?;
            if n > 0 {
                info!("VSOCK Proxy received guest ping: {} bytes", n);
                client_stream.write_all(b"FLEETOS_VSOCK_ACK\n").await?;
            }
        }

        Ok(())
    }
}
