// SPDX-License-Identifier: Apache-2.0
//! Shared test-certificate helper — single source of truth for test TLS material.
//!
//! Every server identity is signed by a per-test root CA (NEVER self-signed per
//! server), so any number of servers can share one trust bundle and all validate
//! against the client's hardcoded `domain_name("fleetos-control")`.
//!
//! INVARIANT: server certs carry SAN "fleetos-control" to match the hardcoded
//! domain name in `src/client/channels.rs` (`build_server_trust_channel` /
//! `build_mtls_channel`). Do not change the SAN without updating those.
use fleetos_agent::error::AgentError;

pub struct TestCa {
    pub cert: rcgen::Certificate,
    pub key: rcgen::KeyPair,
}

impl TestCa {
    /// Generate a fresh root CA for a test.
    pub fn generate() -> Result<Self, AgentError> {
        let mut params = rcgen::CertificateParams::new(vec!["fleetos-control".to_string()])
            .map_err(|e| AgentError::Config(format!("rcgen CA params: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "FleetOS Test CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate()
            .map_err(|e| AgentError::Config(format!("rcgen CA key: {e}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| AgentError::Config(format!("rcgen CA self-sign: {e}")))?;
        Ok(Self { cert, key })
    }

    /// PEM of the root CA — use as the client's trust bundle.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// DER of the root CA.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }

    /// Sign a CSR (SPIFFE SAN carried inside the CSR) -> leaf cert DER.
    /// Delegates to the same signing path control uses.
    pub fn sign_csr(&self, csr_der: &[u8], ttl_secs: u64) -> Result<Vec<u8>, AgentError> {
        use rcgen::{CertificateSigningRequestParams, Issuer};
        use rustls::pki_types::CertificateSigningRequestDer;
        let csr_der_type = CertificateSigningRequestDer::from(csr_der);
        let csr_params = CertificateSigningRequestParams::from_der(&csr_der_type)
            .map_err(|e| AgentError::Config(format!("parse CSR: {e}")))?;
        let mut final_params = csr_params.params;
        let now = time::OffsetDateTime::now_utc();
        final_params.not_before = now;
        final_params.not_after = now + time::Duration::seconds(ttl_secs as i64);
        let issuer = Issuer::from_ca_cert_der(self.cert.der(), &self.key)
            .map_err(|e| AgentError::Config(format!("issuer: {e}")))?;
        let cert = final_params
            .signed_by(&csr_params.public_key, &issuer)
            .map_err(|e| AgentError::Config(format!("sign CSR: {e}")))?;
        Ok(cert.der().to_vec())
    }

    /// A server identity signed by this CA. SAN = "fleetos-control" so the
    /// client's hardcoded `domain_name("fleetos-control")` validates.
    /// Call once per server; every identity shares this CA, so all validate
    /// against `cert_pem()` — this is what makes multi-server tests work.
    pub fn server_identity(&self) -> Result<(String, String), AgentError> {
        let mut params = rcgen::CertificateParams::new(vec!["fleetos-control".to_string()])
            .map_err(|e| AgentError::Config(format!("rcgen server params: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fleetos-control");
        let key = rcgen::KeyPair::generate()
            .map_err(|e| AgentError::Config(format!("rcgen server key: {e}")))?;
        let issuer = rcgen::Issuer::from_ca_cert_der(self.cert.der(), &self.key)
            .map_err(|e| AgentError::Config(format!("rcgen issuer: {e}")))?;
        let cert = params
            .signed_by(&key, &issuer)
            .map_err(|e| AgentError::Config(format!("rcgen server sign: {e}")))?;
        Ok((cert.pem(), key.serialize_pem()))
    }
}
