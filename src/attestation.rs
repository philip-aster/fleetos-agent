use anyhow::{Context, Result};
use fleetos_core::HardwareAttestor;
use fleetos_core::proto::identity::{
    AttestNodeRequest, PcrValue, identity_service_client::IdentityServiceClient,
};
use std::time::Duration;
use tonic::transport::Endpoint;
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
    pub async fn authenticate_host<A: HardwareAttestor>(
        &self,
        attestor: &A,
        join_token: &str,
    ) -> Result<String> {
        info!("Generating TPM hardware quote for host attestation...");

        // 1. Generate fresh 32-byte nonce for TPM quote generation
        let mut nonce = [0u8; 32];
        rand::fill(&mut nonce);

        // 2. Generate TPM quote signed by AK
        let quote = attestor
            .generate_quote(&nonce)
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

        // 3. Connect to IdentityService on control plane with connection timeout
        let endpoint = Endpoint::from_shared(self.control_plane_endpoint.clone())?
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));

        let mut client = IdentityServiceClient::connect(endpoint)
            .await
            .context("Failed to connect to IdentityService on control plane")?;

        // 4. Construct request matching proto fields exactly
        let request = AttestNodeRequest {
            join_token: join_token.to_string(),
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
