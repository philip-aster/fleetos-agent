// SPDX-License-Identifier: Apache-2.0
//! Phase 6.4 — VSOCK attestation handshake (guest-init ↔ agent).
//!
//! Drives the agent's `VsockAttestServer::run_handshake` over a unix
//! socketpair while playing the `fleetos-guest-init` role byte-for-byte per
//! the shared contract in `fleetos_core::vsock_proto` (u32 LE length prefix
//! + postcard payload). Real AF_VSOCK needs a hypervisor and is out of scope
//! for CI; everything above the socket — framing, protocol-version check,
//! nonce discipline, quote verification, fail-closed behavior, and the
//! result-always-sent + config-push contracts — is covered here.
//!
//! Return-value contract for `run_handshake` / `handle_connection`:
//!   Ok(())  — handshake protocol completed (attestation accepted OR cleanly
//!             rejected with AgentAttestResult delivered before close).
//!   Err(..) — protocol-level failure (malformed frame, oversized length
//!             claim, EOF mid-handshake, decode error).
//!
//! Run:
//!   cargo test --test vsock_handshake_flow            (non-production)
//!   cargo test --features production --test vsock_handshake_flow

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use fleetos_agent::error::AgentError;
use fleetos_agent::identity::degraded::DelegatedKeyManager;
use fleetos_agent::vsock_attest::config_push::WorkloadConfigBuilder;
use fleetos_agent::vsock_attest::measure::BootMeasurement;
use fleetos_agent::vsock_attest::measure::compute_boot_measurement;
use fleetos_agent::vsock_attest::verify::VsockQuoteVerifier;
use fleetos_agent::vsock_attest::{VsockAttestServer, WorkloadContext};
use fleetos_core::proto::fleetos::{EnvVar, PodSpec, VolumeMount};
use fleetos_core::vsock_proto::{
    AgentAttestResult, DummyIpRouteConfig, MAX_MESSAGE_BYTES, PROTOCOL_VERSION,
    QUOTE_TYPE_DEV_SOFTWARE, QUOTE_TYPE_HOST_MEASURED, VsockAttestationChallenge,
    VsockAttestationProof, WorkloadConfig, decode_msg, frame_msg,
};

/// Peer CID the test "connects from". Arbitrary (no real VSOCK in CI).
const TEST_CID: u32 = 42;
/// Backstop timeout so no test can hang indefinitely.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Guest-side harness — mirrors fleetos-guest-init/src/protocol.rs framing.
// ---------------------------------------------------------------------------

struct GuestSide {
    stream: UnixStream,
}

#[allow(dead_code)]
#[derive(Debug)]
enum GuestReadError {
    Io(std::io::Error),
    TooLarge(usize),
    Decode(postcard::Error),
}

impl GuestSide {
    fn write_msg<T: serde::Serialize>(&mut self, msg: &T) {
        let framed = frame_msg(msg).expect("frame_msg");
        self.stream.write_all(&framed).expect("guest write");
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).expect("guest raw write");
    }

    fn read_msg<T: serde::de::DeserializeOwned>(&mut self) -> Result<T, GuestReadError> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .map_err(GuestReadError::Io)?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_BYTES {
            return Err(GuestReadError::TooLarge(len));
        }
        let mut buf = vec![0u8; len];
        self.stream
            .read_exact(&mut buf)
            .map_err(GuestReadError::Io)?;
        decode_msg(&buf).map_err(GuestReadError::Decode)
    }

    /// True when the peer has closed the connection. Call only when EOF is
    /// expected (after joining the agent thread, so the close is guaranteed).
    fn sees_eof(&mut self) -> bool {
        let mut b = [0u8; 1];
        matches!(self.stream.read(&mut b), Ok(0))
    }
}

// ---------------------------------------------------------------------------
// Test plumbing
// ---------------------------------------------------------------------------

type HandshakeOutcome = Result<(), AgentError>;

fn spawn_agent_handshake(
    server: Arc<VsockAttestServer>,
) -> (GuestSide, std::thread::JoinHandle<HandshakeOutcome>) {
    let (agent_end, guest_end) = UnixStream::pair().expect("socketpair");
    for sock in [&agent_end, &guest_end] {
        sock.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        sock.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    }
    let agent_fd: OwnedFd = agent_end.into();
    let handle = std::thread::spawn(move || server.run_handshake(agent_fd, TEST_CID));
    (GuestSide { stream: guest_end }, handle)
}

fn make_server() -> Arc<VsockAttestServer> {
    Arc::new(VsockAttestServer::new(
        Arc::new(VsockQuoteVerifier::new()),
        Arc::new(WorkloadConfigBuilder::new(
            "fleet.test.internal".to_string(),
            Arc::new(std::sync::RwLock::new(DelegatedKeyManager::new())),
            3600,
        )),
    ))
}

/// Read the agent's challenge and assert the protocol-version contract.
fn read_challenge(guest: &mut GuestSide) -> VsockAttestationChallenge {
    let challenge: VsockAttestationChallenge = guest.read_msg().expect("challenge frame");
    assert_eq!(
        challenge.protocol_version, PROTOCOL_VERSION,
        "agent must advertise PROTOCOL_VERSION"
    );
    challenge
}

/// Standard workload context registered for TEST_CID.
fn workload_context() -> WorkloadContext {
    WorkloadContext {
        pod_spec: PodSpec {
            tenant_id: "acme".to_string(),
            workload_id: "db".to_string(),
            role: "primary".to_string(),
            env: vec![EnvVar {
                name: "FOO".to_string(),
                value: "bar".to_string(),
            }],
            volume_mounts: vec![VolumeMount {
                name: "scratch".to_string(),
                mount_path: "/scratch".to_string(),
                read_only: false,
            }],
            ..Default::default()
        },
        guest_ip: [10, 0, 0, 2],
        netmask: [255, 255, 255, 0],
        gateway: [10, 0, 0, 1],
    }
}

fn dummy_route() -> DummyIpRouteConfig {
    DummyIpRouteConfig {
        dummy_ip: [240, 0, 0, 45],
        service: "db".to_string(),
        role: "primary".to_string(),
        tenant: "acme".to_string(),
    }
}

/// Write boot artifacts and compute their measurement.
fn boot_artifacts() -> (tempfile::TempDir, BootMeasurement) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("vmlinux"), b"kernel-image").unwrap();
    std::fs::write(dir.path().join("rootfs.erofs"), b"erofs-rootfs").unwrap();
    std::fs::write(dir.path().join("fleetos-guest-init"), b"guest-init-binary").unwrap();
    let m = compute_boot_measurement(
        &dir.path().join("vmlinux"),
        &dir.path().join("rootfs.erofs"),
        &dir.path().join("fleetos-guest-init"),
    )
    .expect("boot measurement");
    (dir, m)
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[cfg(not(feature = "production"))]
#[test]
fn dev_software_quote_accepted_and_config_pushed() {
    let server = make_server();
    server.register_workload_context(TEST_CID, workload_context());
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));

    let challenge = read_challenge(&mut guest);
    // Mirror fleetos-guest-init's DevSoftwareQuoteGenerator layout.
    let mut raw_quote = b"FLEETOS-DEV-QUOTE-V1\0".to_vec();
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_DEV_SOFTWARE,
        raw_quote,
        guest_x25519_pubkey: [0x11; 32],
    });

    let result: AgentAttestResult = guest.read_msg().expect("result");
    assert!(
        result.accepted,
        "dev quote must be accepted: {}",
        result.reason
    );
    let config: WorkloadConfig = guest.read_msg().expect("config pushed");
    assert_eq!(config.trust_domain, "fleet.test.internal");
    assert_eq!(config.tenant_id, "acme");
    assert_eq!(config.service_name, "db");
    assert_eq!(config.role, "primary");

    handle.join().expect("agent thread panicked").unwrap();
    assert!(guest.sees_eof(), "agent must close after config push");
}

#[test]
fn host_measured_quote_accepted_and_context_pushed() {
    let config_builder = Arc::new(WorkloadConfigBuilder::new(
        "fleet.test.internal".to_string(),
        Arc::new(std::sync::RwLock::new(DelegatedKeyManager::new())),
        3600,
    ));
    config_builder.set_dummy_ip_routes(vec![dummy_route()]);
    let server = Arc::new(VsockAttestServer::new(
        Arc::new(VsockQuoteVerifier::new()),
        Arc::clone(&config_builder),
    ));
    let (_dir, measurement) = boot_artifacts();
    server.register_boot_measurement(TEST_CID, measurement.clone());
    server.register_workload_context(TEST_CID, workload_context());

    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let challenge = read_challenge(&mut guest);
    // Guest quote contract: combined_hash first, nonce bound inside.
    let mut raw_quote = measurement.combined_hash.to_vec();
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_HOST_MEASURED,
        raw_quote,
        guest_x25519_pubkey: [0x22; 32],
    });

    let result: AgentAttestResult = guest.read_msg().expect("result");
    assert!(
        result.accepted,
        "host-measured must be accepted: {}",
        result.reason
    );
    let config: WorkloadConfig = guest.read_msg().expect("config pushed");

    // Every context field must survive the wire trip.
    assert_eq!(config.trust_domain, "fleet.test.internal");
    assert_eq!(config.tenant_id, "acme");
    assert_eq!(config.service_name, "db");
    assert_eq!(config.role, "primary");
    assert_eq!(config.guest_ip, [10, 0, 0, 2]);
    assert_eq!(config.netmask, [255, 255, 255, 0]);
    assert_eq!(config.gateway, [10, 0, 0, 1]);
    assert_eq!(
        config.env_vars,
        vec![("FOO".to_string(), "bar".to_string())]
    );
    assert_eq!(config.volume_mounts.len(), 1);
    assert_eq!(config.volume_mounts[0].name, "scratch");
    assert_eq!(config.dummy_ip_routes.len(), 1);
    assert_eq!(config.dummy_ip_routes[0].dummy_ip, [240, 0, 0, 45]);
    assert_eq!(config.workload_binary_path, "/usr/bin/db");

    handle.join().expect("agent thread panicked").unwrap();
    assert!(guest.sees_eof(), "exactly one config, then clean close");
}

#[test]
fn host_measured_accepted_without_context_pushes_fallback_config() {
    let server = make_server();
    let (_dir, measurement) = boot_artifacts();
    server.register_boot_measurement(TEST_CID, measurement.clone());
    // Deliberately no workload context registered for TEST_CID.

    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let challenge = read_challenge(&mut guest);
    let mut raw_quote = measurement.combined_hash.to_vec();
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_HOST_MEASURED,
        raw_quote,
        guest_x25519_pubkey: [0x33; 32],
    });

    let result: AgentAttestResult = guest.read_msg().expect("result");
    assert!(result.accepted, "{}", result.reason);
    let config: WorkloadConfig = guest.read_msg().expect("fallback config pushed");
    assert!(
        config.tenant_id.is_empty(),
        "fallback config carries no context"
    );
    assert_eq!(config.trust_domain, "fleet.test.internal");

    handle.join().expect("agent thread panicked").unwrap();
    assert!(guest.sees_eof());
}

// ---------------------------------------------------------------------------
// Fail-closed matrix — every case: rejected, non-empty reason, no config, EOF.
// ---------------------------------------------------------------------------

fn assert_rejected(
    guest: &mut GuestSide,
    handle: std::thread::JoinHandle<HandshakeOutcome>,
    needle: &str,
) {
    // A clean rejection is a *completed* handshake: the agent delivered
    // AgentAttestResult { accepted: false } and closed cleanly, so
    // handle_connection returns Ok(()). Only protocol-level failures
    // (malformed frame, oversized length, EOF mid-handshake) surface as
    // Err — those have their own dedicated tests.
    let outcome = handle.join().expect("agent thread panicked");
    outcome.unwrap_or_else(|e| panic!("clean rejection must complete the handshake, got Err: {e}"));

    // Result bytes were buffered before the agent closed, so they are still
    // readable after join. This pins the result-always-sent contract.
    let result: AgentAttestResult = guest
        .read_msg()
        .expect("AgentAttestResult must be delivered even on rejection");
    assert!(!result.accepted, "handshake must be rejected");
    assert!(!result.reason.is_empty(), "rejection must carry a reason");
    assert!(
        result.reason.contains(needle),
        "reason {:?} should mention {:?}",
        result.reason,
        needle
    );
    assert!(guest.sees_eof(), "no config after rejection, then close");
}

#[cfg(not(feature = "production"))]
#[test]
fn dev_quote_nonce_mismatch_rejected() {
    let server = make_server();
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let _challenge = read_challenge(&mut guest);
    // Quote bound to a nonce the agent never issued.
    let mut raw_quote = b"FLEETOS-DEV-QUOTE-V1\0".to_vec();
    raw_quote.extend_from_slice(&[0xAAu8; 32]);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_DEV_SOFTWARE,
        raw_quote,
        guest_x25519_pubkey: [0x11; 32],
    });
    assert_rejected(&mut guest, handle, "nonce");
}

#[test]
fn host_measured_wrong_hash_rejected() {
    let server = make_server();
    let (_dir, measurement) = boot_artifacts();
    server.register_boot_measurement(TEST_CID, measurement);

    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let challenge = read_challenge(&mut guest);
    let mut raw_quote = vec![0xEEu8; 32]; // wrong combined hash
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_HOST_MEASURED,
        raw_quote,
        guest_x25519_pubkey: [0x22; 32],
    });
    assert_rejected(&mut guest, handle, "measurement");
}

#[test]
fn host_measured_unknown_cid_rejected() {
    let server = make_server();
    let (_dir, measurement) = boot_artifacts();
    // Measurement registered for a DIFFERENT CID than the one we connect as.
    server.register_boot_measurement(99, measurement.clone());

    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let challenge = read_challenge(&mut guest);
    let mut raw_quote = measurement.combined_hash.to_vec();
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_HOST_MEASURED,
        raw_quote,
        guest_x25519_pubkey: [0x22; 32],
    });
    assert_rejected(&mut guest, handle, "measurement");
}

#[test]
fn unknown_quote_type_rejected() {
    let server = make_server();
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let _challenge = read_challenge(&mut guest);
    guest.write_msg(&VsockAttestationProof {
        quote_type: 42, // not a defined QUOTE_TYPE_*
        raw_quote: vec![0u8; 64],
        guest_x25519_pubkey: [0x11; 32],
    });
    assert_rejected(&mut guest, handle, "quote_type");
}

#[test]
fn malformed_proof_frame_terminates_cleanly() {
    let server = make_server();
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let _challenge = read_challenge(&mut guest);
    // Well-formed frame, garbage postcard payload.
    let payload = b"not-a-postcard-proof";
    let mut frame = (payload.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(payload);
    guest.write_raw(&frame);

    let outcome = handle.join().expect("agent thread panicked");
    outcome.expect_err("decode failure must surface as Err");
    assert!(guest.sees_eof(), "agent closes without sending a config");
}

#[test]
fn oversized_frame_rejected_cleanly() {
    let server = make_server();
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let _challenge = read_challenge(&mut guest);
    // Claim a payload beyond MAX_MESSAGE_BYTES; send only the header.
    guest.write_raw(&((MAX_MESSAGE_BYTES + 1) as u32).to_le_bytes());

    let outcome = handle.join().expect("agent thread panicked");
    outcome.expect_err("oversized frame must be rejected");
    assert!(guest.sees_eof());
}

#[test]
fn guest_disconnect_mid_handshake_is_clean() {
    let server = make_server();
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let _challenge = read_challenge(&mut guest);
    drop(guest); // guest vanishes after reading the challenge

    let outcome = handle.join().expect("agent thread panicked");
    outcome.expect_err("EOF mid-handshake must surface as Err, not hang");
}

// ---------------------------------------------------------------------------
// Production behavior
// ---------------------------------------------------------------------------

#[cfg(feature = "production")]
#[test]
fn prod_dev_software_rejected() {
    let server = make_server();
    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let challenge = read_challenge(&mut guest);
    let mut raw_quote = b"FLEETOS-DEV-QUOTE-V1\0".to_vec();
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_DEV_SOFTWARE,
        raw_quote,
        guest_x25519_pubkey: [0x11; 32],
    });
    assert_rejected(&mut guest, handle, "production");
}

#[cfg(feature = "production")]
#[test]
fn prod_host_measured_still_accepted() {
    let server = make_server();
    let (_dir, measurement) = boot_artifacts();
    server.register_boot_measurement(TEST_CID, measurement.clone());
    server.register_workload_context(TEST_CID, workload_context());

    let (mut guest, handle) = spawn_agent_handshake(Arc::clone(&server));
    let challenge = read_challenge(&mut guest);
    let mut raw_quote = measurement.combined_hash.to_vec();
    raw_quote.extend_from_slice(&challenge.nonce);
    guest.write_msg(&VsockAttestationProof {
        quote_type: QUOTE_TYPE_HOST_MEASURED,
        raw_quote,
        guest_x25519_pubkey: [0x22; 32],
    });

    let result: AgentAttestResult = guest.read_msg().expect("result");
    assert!(result.accepted, "{}", result.reason);
    let _config: WorkloadConfig = guest.read_msg().expect("config pushed");
    handle.join().expect("agent thread panicked").unwrap();
    assert!(guest.sees_eof());
}
