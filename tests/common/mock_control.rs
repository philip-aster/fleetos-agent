#![allow(dead_code)]
// SPDX-License-Identifier: Apache-2.0
//! Mock control plane for join-flow integration tests.
//!
//! Real TLS (rcgen self-signed CA + server cert with SAN "fleetos-control" to
//! match the hardcoded domain_name in build_server_trust_channel), real gRPC
//! services (AttestationService + CaService), real crypto:
//!
//! - Insecure: single-use join-token verification + nonce echo + CSR signing.
//! - Secure:   TPM2_MakeCredential via swtpm, HMAC activation-proof check,
//!             CSR signing. No plaintext shortcut anywhere.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::Mutex;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use fleetos_agent::error::AgentError;
use fleetos_core::proto::fleetos::{
    ActivationChallenge, ActivationProof, ActivationRequest, AttestationQuote, AttestedIdentity,
    CsrRequest, NonceRequest, NonceResponse, QuoteType, SvidResponse, TrustBundle,
    TrustBundleRequest,
    attestation_service_server::{AttestationService, AttestationServiceServer},
    ca_service_server::{CaService, CaServiceServer},
};

pub use super::certs::TestCa;

/// Pending TPM credential-activation session (secure join).
struct ActivationSession {
    seed: [u8; 32],
    server_nonce: Vec<u8>,
}

/// Mock control plane state shared between AttestationService and CaService.
pub struct MockControlPlane {
    /// Expected join token (insecure mode). Single-use: consumed on first
    /// successful SubmitQuote (mirrors cluster_token single-use in control).
    join_token: Arc<Mutex<Option<String>>>,
    /// Issued nonces: nonce bytes → claimed SPIFFE ID.
    nonces: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    /// CA for SVID signing + TLS.
    ca: Arc<TestCa>,
    /// Trust domain returned by GetTrustBundle.
    trust_domain: String,
    /// Monotonic SVID version counter.
    next_version: AtomicU64,
    /// Secure join: pending activation sessions (seed known only to mock+TPM).
    sessions: Arc<Mutex<Vec<ActivationSession>>>,
    /// TPM endpoint for MakeCredential (secure mode only).
    tpm_endpoint: Option<fleetos_core::attestation::tpm::TpmEndpoint>,
}

#[tonic::async_trait]
impl AttestationService for MockControlPlane {
    async fn request_nonce(
        &self,
        request: Request<NonceRequest>,
    ) -> Result<Response<NonceResponse>, Status> {
        let claimed = request.into_inner().claimed_spiffe_id;
        let nonce: [u8; 32] = rand::random();
        self.nonces.lock().await.insert(nonce.to_vec(), claimed);
        Ok(Response::new(NonceResponse {
            nonce: nonce.to_vec(),
        }))
    }

    async fn submit_quote(
        &self,
        request: Request<AttestationQuote>,
    ) -> Result<Response<AttestedIdentity>, Status> {
        let quote = request.into_inner();

        // 1. Join-token gate, single-use.
        {
            let mut slot = self.join_token.lock().await;
            match slot.as_ref() {
                Some(expected) if *expected == quote.join_token => {
                    *slot = None; // consumed
                }
                _ => return Err(Status::unauthenticated("invalid or consumed join token")),
            }
        }

        // 2. Nonce echo check; recover the claimed SPIFFE ID bound at
        //    RequestNonce time.
        let claimed = {
            let mut nonces = self.nonces.lock().await;
            nonces
                .remove(&quote.raw_quote)
                .ok_or_else(|| Status::unauthenticated("nonce mismatch or expired"))?
        };

        // 3. Sealing pubkey must be exactly 32 bytes (X25519).
        if quote.agent_x25519_pubkey.len() != 32 {
            return Err(Status::invalid_argument(
                "agent_x25519_pubkey must be exactly 32 bytes",
            ));
        }

        Ok(Response::new(AttestedIdentity {
            claimed_spiffe_id: claimed,
            quote_type: QuoteType::Vsock as i32,
            pcr_digest: Vec::new(),
            verified_at_unix: 0,
        }))
    }

    async fn request_activation(
        &self,
        request: Request<ActivationRequest>,
    ) -> Result<Response<ActivationChallenge>, Status> {
        let req = request.into_inner();
        let endpoint = self
            .tpm_endpoint
            .as_ref()
            .ok_or_else(|| Status::unavailable("mock not configured for secure join (no TPM)"))?;

        let seed: [u8; 32] = rand::random();
        let server_nonce: [u8; 32] = rand::random();

        // TPM2_MakeCredential: wrap the seed for the (EK, AK) pair. Only the
        // holder of the EK private key (the agent's TPM) can recover it.
        let (credential_blob, secret) = fleetos_core::attestation::tpm::make_credential(
            endpoint,
            &req.ek_pub,
            &req.ak_pub,
            &seed,
        )
        .map_err(|e| Status::internal(format!("MakeCredential failed: {e}")))?;

        self.sessions.lock().await.push(ActivationSession {
            seed,
            server_nonce: server_nonce.to_vec(),
        });

        Ok(Response::new(ActivationChallenge {
            credential_blob,
            secret,
            server_nonce: server_nonce.to_vec(),
        }))
    }

    async fn submit_activation_proof(
        &self,
        request: Request<ActivationProof>,
    ) -> Result<Response<SvidResponse>, Status> {
        let proof = request.into_inner();

        // Locate the session whose HMAC(seed, server_nonce) matches the proof.
        // Matching proves the agent recovered the seed, i.e. holds the EK
        // private key (TPM2_ActivateCredential succeeded).
        {
            let mut sessions = self.sessions.lock().await;
            let pos = sessions
                .iter()
                .position(|s| {
                    // FIX: Use the correct core attestation primitive (BLAKE3 keyed hash)
                    fleetos_core::attestation::compute_activation_proof(&s.seed, &s.server_nonce)
                        .as_slice()
                        == proof.hmac.as_slice()
                })
                .ok_or_else(|| Status::unauthenticated("activation proof HMAC mismatch"))?;
            sessions.remove(pos);
        }

        // Structural PCR-quote checks (full PCR-policy verification mirrors
        // control's pcr.rs path; the HMAC above is the cryptographic gate).
        if proof.quote.is_empty() || proof.quote_signature.is_empty() {
            return Err(Status::invalid_argument("missing PCR quote"));
        }
        if proof.agent_x25519_pubkey.len() != 32 {
            return Err(Status::invalid_argument(
                "agent_x25519_pubkey must be exactly 32 bytes",
            ));
        }

        // Sign the CSR (SPIFFE SAN is inside the CSR).
        let cert_der = self
            .ca
            .sign_csr(&proof.csr_der, 3600)
            .map_err(|e| Status::internal(format!("CSR signing failed: {e}")))?;

        let version = self.next_version.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(SvidResponse {
            cert_chain_der: cert_der,
            // CR-10 secure mode: EMPTY — the node holds its own private key.
            keypair_der: Vec::new(),
            svid_version: version,
        }))
    }
}

#[tonic::async_trait]
impl CaService for MockControlPlane {
    async fn submit_csr(
        &self,
        request: Request<CsrRequest>,
    ) -> Result<Response<SvidResponse>, Status> {
        let csr_der = request.into_inner().csr_der;
        if csr_der.is_empty() {
            return Err(Status::invalid_argument("empty CSR"));
        }
        let cert_der = self
            .ca
            .sign_csr(&csr_der, 3600)
            .map_err(|e| Status::internal(format!("CSR signing failed: {e}")))?;
        let version = self.next_version.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(SvidResponse {
            cert_chain_der: cert_der,
            keypair_der: Vec::new(),
            svid_version: version,
        }))
    }

    async fn get_trust_bundle(
        &self,
        _request: Request<TrustBundleRequest>,
    ) -> Result<Response<TrustBundle>, Status> {
        Ok(Response::new(TrustBundle {
            trust_domain: self.trust_domain.clone(),
            roots_der: vec![self.ca.cert_der()],
        }))
    }
}

/// Configuration for spawning a mock control plane.
pub struct MockConfig {
    /// Expected join token (insecure mode). None = secure mode.
    pub join_token: Option<String>,
    /// Trust domain reported by GetTrustBundle.
    pub trust_domain: String,
    /// TPM endpoint for MakeCredential (secure mode only).
    pub tpm_endpoint: Option<fleetos_core::attestation::tpm::TpmEndpoint>,
}

/// Handle to a running mock control plane.
pub struct MockHandle {
    /// "127.0.0.1:<port>" — use as config.control.address.
    pub address: String,
    /// CA certificate PEM — write to config.control.trust_bundle_path.
    pub ca_pem: String,
}

/// Spawn the mock control plane: real TLS listener on an ephemeral port,
/// AttestationService + CaService registered.
pub async fn spawn_mock_control_plane(cfg: MockConfig) -> Result<MockHandle, AgentError> {
    // rustls 0.23+ requires a process-level crypto provider to be explicitly
    // installed. We install the ring provider here so tonic's TLS setup succeeds.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca = Arc::new(TestCa::generate()?);
    let (server_cert_pem, server_key_pem) = ca.server_identity()?;

    // ... rest of the function

    let mock = Arc::new(MockControlPlane {
        join_token: Arc::new(Mutex::new(cfg.join_token)),
        nonces: Arc::new(Mutex::new(HashMap::new())),
        ca: ca.clone(),
        trust_domain: cfg.trust_domain,
        next_version: AtomicU64::new(1),
        sessions: Arc::new(Mutex::new(Vec::new())),
        tpm_endpoint: cfg.tpm_endpoint,
    });

    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let tls = ServerTlsConfig::new().identity(identity);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| AgentError::Config(format!("mock bind: {e}")))?;
    let addr = listener
        .local_addr()
        .map_err(|e| AgentError::Config(format!("mock local_addr: {e}")))?;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    tokio::spawn(async move {
        let _ = Server::builder()
            .tls_config(tls)
            .expect("mock TLS config")
            .add_service(AttestationServiceServer::from_arc(mock.clone()))
            .add_service(CaServiceServer::from_arc(mock))
            .serve_with_incoming(incoming)
            .await;
    });

    Ok(MockHandle {
        address: addr.to_string(),
        ca_pem: ca.cert_pem(),
    })
}
