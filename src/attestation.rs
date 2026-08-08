// fleetos-agent/src/attestation.rs

use anyhow::{Context, Result};
use fleetos_core::HardwareAttestor;
use fleetos_core::proto::identity::{
    AttestNodeRequest, PcrValue, identity_service_client::IdentityServiceClient,
};
use tracing::info;

pub struct BootAttestor {
    control_plane_endpoint: String,
}

impl BootAttestor {
    pub fn new(control_plane_endpoint: String) -> Self {
        Self {
            control_plane_endpoint,
        }
    }

    /// Generates hardware attestation quote and authenticates with IdentityService on control plane
    pub async fn authenticate_host<A: HardwareAttestor>(&self, attestor: &A) -> Result<String> {
        info!("Generating TPM hardware quote for node attestation...");

        // 1. Generate TPM quote with a nonce
        let quote = attestor
            .generate_quote(b"fleetos-attestation-nonce")
            .await
            .context("Failed to generate TPM quote")?;

        let pcr_values = quote
            .pcr_values
            .into_iter()
            .map(|p| PcrValue {
                index: p.pcr_index,
                digest: p.digest,
            })
            .collect();

        // 2. Connect to IdentityService on control plane
        let mut client = IdentityServiceClient::connect(self.control_plane_endpoint.clone())
            .await
            .context("Failed to connect to IdentityService on control plane")?;

        // 3. Submit attestation request
        let request = AttestNodeRequest {
            join_token: "cluster-bootstrap-token".to_string(),
            public_identity_key: quote.public_identity_key,
            signature_quote: quote.signature_quote,
            pcr_values,
        };

        let response = client
            .attest_node(request)
            .await
            .context("Node hardware attestation rejected by control plane")?
            .into_inner();

        info!(
            "Host attestation successful! Assigned SPIFFE ID: {}",
            response.spiffe_id
        );

        Ok(response.spiffe_id)
    }
}
