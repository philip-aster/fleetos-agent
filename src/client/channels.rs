// SPDX-License-Identifier: Apache-2.0
//! TLS channel construction for gRPC connections to fleetos-control.
//!
//! Two modes:
//! 1. Server-trust TLS (pre-SVID join leg): trust bundle only.
//! 2. mTLS (post-SVID): trust bundle + SVID cert + SVID key.
//!
//! Channels are rebuilt when the SVID generation bumps.

use crate::error::AgentError;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

/// Build a server-trust TLS channel (for the pre-SVID join leg).
pub async fn build_server_trust_channel(
    address: &str,
    trust_bundle_pem: &str,
) -> Result<Channel, AgentError> {
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(tonic::transport::Certificate::from_pem(trust_bundle_pem))
        .domain_name("fleetos-control");

    let channel = Endpoint::from_shared(address.to_string())
        .map_err(|e| AgentError::Config(format!("invalid endpoint: {}", e)))?
        .tls_config(tls_config)
        .map_err(AgentError::GrpcTransport)?
        .connect()
        .await
        .map_err(AgentError::GrpcTransport)?;

    Ok(channel)
}

/// Build an mTLS channel (for post-SVID authenticated RPCs).
pub async fn build_mtls_channel(
    address: &str,
    trust_bundle_pem: &str,
    cert_chain_der: &[Vec<u8>],
    private_key_der: &[u8],
) -> Result<Channel, AgentError> {
    // Convert DER to PEM for tonic's Identity builder
    let cert_pem = ders_to_pem(cert_chain_der, "CERTIFICATE");
    let key_pem = der_to_pem(private_key_der, "PRIVATE KEY");

    let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
    let ca_cert = tonic::transport::Certificate::from_pem(trust_bundle_pem);

    let tls_config = ClientTlsConfig::new()
        .ca_certificate(ca_cert)
        .identity(identity)
        .domain_name("fleetos-control");

    let channel = Endpoint::from_shared(address.to_string())
        .map_err(|e| AgentError::Config(format!("invalid endpoint: {}", e)))?
        .tls_config(tls_config)
        .map_err(AgentError::GrpcTransport)?
        .connect()
        .await
        .map_err(AgentError::GrpcTransport)?;

    Ok(channel)
}

/// Helper to convert a list of DER certificates to a single PEM string.
fn ders_to_pem(ders: &[Vec<u8>], label: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let mut pem = String::new();
    for der in ders {
        let b64 = STANDARD.encode(der);
        pem.push_str(&format!("-----BEGIN {}-----\n", label));
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str(&format!("-----END {}-----\n", label));
    }
    pem
}

/// Helper to convert a single DER key to a PEM string.
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let b64 = STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}
