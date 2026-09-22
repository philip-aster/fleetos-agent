// SPDX-License-Identifier: Apache-2.0
//! VSOCK attestation server — the agent leg of CR-CORE-6.
//!
//! Listens on AF_VSOCK (HOST_CID=2, port 0x4649) for incoming connections
//! from `fleetos-guest-init` running as PID 1 inside MicroVMs. Drives the
//! strict 4-step handshake defined in `fleetos_core::vsock_proto`:
//!
//!   1. Agent → Guest: `VsockAttestationChallenge`
//!   2. Guest → Agent: `VsockAttestationProof`
//!   3. Agent → Guest: `AgentAttestResult` (MUST be sent; never just close)
//!   4. If accepted, Agent → Guest: `WorkloadConfig`
//!
//! The wire types, framing helpers, and quote-type constants all live in
//! `fleetos_core::vsock_proto` (feature `vsock-attest`). This module owns
//! the socket I/O and the handshake orchestration.

pub mod config_push;
pub mod measure;
pub mod verify;

use std::collections::HashMap;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::watch;

use crate::error::AgentError;

use self::measure::BootMeasurement;
use self::verify::VsockQuoteVerifier;

/// The VSOCK attestation server. One instance per hosting agent.
///
/// Binds AF_VSOCK on `HOST_CID=2`, port `VSOCK_PORT` (0x4649) and accepts
/// incoming connections from guests. Each connection drives the 4-step
/// handshake. Verification is fail-closed: any failure sends an
/// `AgentAttestResult` with `accepted: false` and closes the connection.
pub struct VsockAttestServer {
    /// Verifier for guest quotes.
    verifier: Arc<VsockQuoteVerifier>,
    /// Boot measurements indexed by guest CID. Populated when the agent
    /// launches a MicroVM (Batch 10). Used by host-measured verification.
    boot_measurements: Arc<RwLock<HashMap<u32, BootMeasurement>>>,
    /// Config push builder.
    config_builder: Arc<config_push::WorkloadConfigBuilder>,
}

impl VsockAttestServer {
    pub fn new(
        verifier: Arc<VsockQuoteVerifier>,
        config_builder: Arc<config_push::WorkloadConfigBuilder>,
    ) -> Self {
        Self {
            verifier,
            boot_measurements: Arc::new(RwLock::new(HashMap::new())),
            config_builder,
        }
    }

    /// Register a boot measurement for a guest CID.
    ///
    /// Called by the workload launcher (Batch 10) before bringing up the
    /// MicroVM's network. The measurement is used by host-measured
    /// verification to confirm the guest is running expected boot artifacts.
    pub fn register_boot_measurement(&self, cid: u32, measurement: BootMeasurement) {
        self.boot_measurements.write().insert(cid, measurement);
    }

    /// Remove the boot measurement for a guest CID (on VM teardown).
    pub fn unregister_boot_measurement(&self, cid: u32) {
        self.boot_measurements.write().remove(&cid);
    }

    /// Run the accept loop. Blocks until the shutdown signal fires.
    ///
    /// Each incoming connection is handled in a dedicated blocking task
    /// (VSOCK I/O is synchronous, matching the guest-init pattern).
    pub async fn run(&self, mut shutdown: watch::Receiver<bool>) -> Result<(), AgentError> {
        let listener = vsock_listen()?;
        let listener_raw = listener.as_raw_fd();
        tracing::info!(
            cid = fleetos_core::vsock_proto::HOST_CID,
            port = fleetos_core::vsock_proto::VSOCK_PORT,
            "VSOCK attestation server listening"
        );

        let verifier = self.verifier.clone();
        let measurements = self.boot_measurements.clone();
        let config_builder = self.config_builder.clone();

        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!("VSOCK attestation server shutting down");
                        break;
                    }
                }
                accept_result = tokio::task::spawn_blocking(move || {
                    vsock_accept(listener_raw)
                }) => {
                    match accept_result {
                        Ok(Ok((stream, peer_cid))) => {
                            tracing::info!(peer_cid, "VSOCK connection accepted");
                            let v = verifier.clone();
                            let m = measurements.clone();
                            let cb = config_builder.clone();
                            tokio::task::spawn_blocking(move || {
                                if let Err(e) = handle_connection(stream, peer_cid, &v, &m, &cb) {
                                    tracing::warn!(peer_cid, error = %e, "VSOCK handshake failed");
                                }
                            });
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "VSOCK accept failed");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "VSOCK accept task panicked");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Handle a single VSOCK connection: drive the 4-step handshake.
fn handle_connection(
    stream: std::os::fd::OwnedFd,
    peer_cid: u32,
    verifier: &VsockQuoteVerifier,
    measurements: &RwLock<HashMap<u32, BootMeasurement>>,
    config_builder: &config_push::WorkloadConfigBuilder,
) -> Result<(), AgentError> {
    use fleetos_core::vsock_proto::*;
    use std::os::fd::AsRawFd;

    let stream = std::fs::File::from(stream);
    let fd = stream.as_raw_fd();

    // Step 1: Send challenge.
    let nonce = fleetos_core::nonce::Nonce::generate();
    let challenge = VsockAttestationChallenge {
        protocol_version: PROTOCOL_VERSION,
        nonce: *nonce.as_bytes(),
    };
    write_msg(fd, &challenge)?;
    tracing::debug!(peer_cid, "challenge sent");

    // Step 2: Receive proof.
    let proof: VsockAttestationProof = read_msg(fd)?;
    tracing::debug!(peer_cid, quote_type = proof.quote_type, "proof received");

    // Step 3: Verify and send result.
    let measurement = measurements.read().get(&peer_cid).cloned();
    let verification = verifier.verify(&proof, &nonce, peer_cid, measurement.as_ref());

    let result = match &verification {
        Ok(_) => AgentAttestResult {
            accepted: true,
            reason: String::new(),
        },
        Err(e) => AgentAttestResult {
            accepted: false,
            reason: e.to_string(),
        },
    };

    write_msg(fd, &result)?;
    tracing::debug!(peer_cid, accepted = result.accepted, "result sent");

    if result.accepted {
        // Step 4: Push WorkloadConfig using the verified guest identity.
        let verified = verification.unwrap();
        let config = config_builder.build(&verified)?;
        write_msg(fd, &config)?;
        tracing::info!(peer_cid, "workload config pushed");
    }

    Ok(())
}

// --- VSOCK socket helpers (blocking, libc-based) ---

const AF_VSOCK: libc::c_int = 40;

#[repr(C)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

/// Bind and listen on AF_VSOCK.
fn vsock_listen() -> Result<std::os::fd::OwnedFd, AgentError> {
    unsafe {
        let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(AgentError::Internal(format!(
                "socket(AF_VSOCK) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut addr: SockaddrVm = std::mem::zeroed();
        addr.svm_family = AF_VSOCK as u16;
        addr.svm_port = fleetos_core::vsock_proto::VSOCK_PORT;
        addr.svm_cid = fleetos_core::vsock_proto::HOST_CID;

        let ret = libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            std::mem::size_of::<SockaddrVm>() as libc::socklen_t,
        );
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(AgentError::Internal(format!("bind() failed: {}", err)));
        }

        let ret = libc::listen(fd, 16);
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(AgentError::Internal(format!("listen() failed: {}", err)));
        }

        Ok(std::os::fd::OwnedFd::from_raw_fd(fd))
    }
}

/// Accept a single VSOCK connection. Returns the stream fd and the peer CID.
fn vsock_accept(listener_fd: i32) -> Result<(std::os::fd::OwnedFd, u32), AgentError> {
    use std::os::fd::FromRawFd;

    let mut addr: SockaddrVm = unsafe { std::mem::zeroed() };
    let mut addr_len = std::mem::size_of::<SockaddrVm>() as libc::socklen_t;

    let fd = unsafe {
        libc::accept(
            listener_fd,
            &mut addr as *mut SockaddrVm as *mut libc::sockaddr,
            &mut addr_len,
        )
    };
    if fd < 0 {
        return Err(AgentError::Internal(format!(
            "accept() failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok((
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) },
        addr.svm_cid,
    ))
}

// --- Framing I/O (mirrors guest-init's protocol.rs) ---

fn write_msg<T: serde::Serialize>(fd: i32, msg: &T) -> Result<(), AgentError> {
    use std::io::Write;

    let framed = fleetos_core::vsock_proto::frame_msg(msg)
        .map_err(|e| AgentError::Internal(format!("frame_msg failed: {}", e)))?;

    let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };
    stream
        .write_all(&framed)
        .map_err(|e| AgentError::Internal(format!("write failed: {}", e)))?;
    // Don't close the fd — File::from_raw_fd takes ownership.
    std::mem::forget(stream);
    Ok(())
}

fn read_msg<T: serde::de::DeserializeOwned>(fd: i32) -> Result<T, AgentError> {
    use std::io::Read;

    let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| AgentError::Internal(format!("read length failed: {}", e)))?;
    let len = u32::from_le_bytes(len_buf) as usize;

    if len > fleetos_core::vsock_proto::MAX_MESSAGE_BYTES {
        std::mem::forget(stream);
        return Err(AgentError::Internal(format!(
            "message too large: {} bytes (max {})",
            len,
            fleetos_core::vsock_proto::MAX_MESSAGE_BYTES
        )));
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .map_err(|e| AgentError::Internal(format!("read payload failed: {}", e)))?;
    std::mem::forget(stream);

    fleetos_core::vsock_proto::decode_msg(&buf)
        .map_err(|e| AgentError::Internal(format!("decode_msg failed: {}", e)))
}
