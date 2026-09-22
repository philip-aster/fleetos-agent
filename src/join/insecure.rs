// SPDX-License-Identifier: Apache-2.0
//! Insecure join flow: join-token only, structural quote checks.
//!
//! TESTING ONLY. Compiled out of production builds.
//! The quote is NOT cryptographically verified; control accepts it based
//! solely on possession of the join token.
use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::storage::Storage;

#[cfg(not(feature = "production"))]
pub async fn perform_insecure_join(
    config: &AgentConfig,
    storage: &Storage,
) -> Result<(), AgentError> {
    use crate::client::channels::build_server_trust_channel;
    use crate::client::retry::{RetryAction, classify_error};
    use crate::identity::{
        keystore::{SensitiveStore, TpmSealedStore},
        svid,
    };
    use fleetos_core::SpiffeId;
    use fleetos_core::attestation::quote::TpmQuote;
    use fleetos_core::proto::identity::{
        AttestationQuote as ProtoAttestationQuote, AttestationServiceClient, CaServiceClient,
        CsrRequest, NonceRequest, QuoteType, TrustBundleRequest,
    };
    use fleetos_core::spiffe::IdKind;

    tracing::warn!("starting INSECURE join flow (testing only)");

    let tpm_endpoint = config.tpm_endpoint();
    let sealed_store = TpmSealedStore::new(tpm_endpoint);

    // 1. Generate and store X25519 sealing keypair
    let sealing_pubkey_bytes = sealed_store.generate_and_store_sealing_key(storage)?;
    let sealing_pubkey = fleetos_core::crypto::RecipientX25519Pubkey(sealing_pubkey_bytes);

    // 2. Build node SPIFFE ID
    let node_spiffe_id = SpiffeId::new(
        &config.node.trust_domain,
        "system",
        IdKind::Node,
        &config.node.name,
    );

    // 3. Connect to control plane
    let trust_bundle_path = config
        .join
        .trust_bundle_path
        .as_ref()
        .unwrap_or(&config.control.trust_bundle_path);
    let trust_bundle_pem = std::fs::read_to_string(trust_bundle_path)
        .map_err(|e| AgentError::Config(format!("failed to read trust bundle: {}", e)))?;

    let mut channel =
        build_server_trust_channel(&config.control.address, &trust_bundle_pem).await?;
    let mut att_client = AttestationServiceClient::new(channel.clone());
    let mut ca_client = CaServiceClient::new(channel.clone());
    let mut redirect_hops = 0;

    // 4. RequestNonce
    let nonce_resp = loop {
        let req = NonceRequest {
            claimed_spiffe_id: node_spiffe_id.to_string(),
        };
        match att_client.request_nonce(req).await {
            Ok(resp) => break resp.into_inner(),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, delay } => {
                    redirect_hops += 1;
                    tokio::time::sleep(delay).await;
                    channel = build_server_trust_channel(&new_target, &trust_bundle_pem).await?;
                    att_client = AttestationServiceClient::new(channel.clone());
                    ca_client = CaServiceClient::new(channel.clone());
                }
                RetryAction::RetrySameTarget { delay } => {
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::JoinFailed(format!(
                        "RequestNonce failed: {}",
                        reason
                    )));
                }
            },
        }
    };

    // 5. Build structural TpmQuote (not cryptographically valid)
    let fake_quote = TpmQuote {
        quote_bytes: vec![],
        signature: vec![],
        nonce: nonce_resp.nonce,
        pcr_selection: vec![],
        attestation_key_pub: vec![],
    };
    let raw_quote = postcard::to_allocvec(&fake_quote).map_err(AgentError::Serialization)?;

    // 6. SubmitQuote — use the PROTO-generated AttestationQuote type
    let _attested_identity = loop {
        let quote = ProtoAttestationQuote {
            quote_type: QuoteType::Tpm2 as i32,
            raw_quote: raw_quote.clone(),
            raw_signature: vec![],
            join_token: config.join.token.clone(),
            agent_x25519_pubkey: sealing_pubkey.0.to_vec(),
        };
        match att_client.submit_quote(quote).await {
            Ok(resp) => break resp.into_inner(),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, delay } => {
                    redirect_hops += 1;
                    tokio::time::sleep(delay).await;
                    channel = build_server_trust_channel(&new_target, &trust_bundle_pem).await?;
                    att_client = AttestationServiceClient::new(channel.clone());
                    ca_client = CaServiceClient::new(channel.clone());
                }
                RetryAction::RetrySameTarget { delay } => {
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::JoinFailed(format!(
                        "SubmitQuote failed: {}",
                        reason
                    )));
                }
            },
        }
    };

    // 7. Generate node SVID keypair and CSR
    let svid_keypair = rcgen::KeyPair::generate()
        .map_err(|e| AgentError::Attestation(format!("rcgen keygen failed: {}", e)))?;
    let svid_priv_der = svid_keypair.serialize_der();
    sealed_store.store_sealed(storage, b"svid_private_key", &svid_priv_der)?;

    let csr = fleetos_core::spiffe::ca::build_csr(&node_spiffe_id, &svid_keypair)
        .map_err(|e| AgentError::Attestation(format!("build_csr failed: {}", e)))?;

    // 8. SubmitCsr
    let svid_resp = loop {
        let req = CsrRequest {
            csr_der: csr.der.clone(),
        };
        match ca_client.submit_csr(req).await {
            Ok(resp) => break resp.into_inner(),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, delay } => {
                    redirect_hops += 1;
                    tokio::time::sleep(delay).await;
                    channel = build_server_trust_channel(&new_target, &trust_bundle_pem).await?;
                    ca_client = CaServiceClient::new(channel.clone());
                }
                RetryAction::RetrySameTarget { delay } => {
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::JoinFailed(format!(
                        "SubmitCsr failed: {}",
                        reason
                    )));
                }
            },
        }
    };

    // 9. Install SVID — wrap single cert in a vec for the chain
    let current_gen = svid::load(storage)?.generation;
    svid::store(
        storage,
        &[svid_resp.cert_chain_der],
        svid_resp.svid_version,
        current_gen,
    )?;

    // 10. GetTrustBundle
    let _bundle = ca_client
        .get_trust_bundle(TrustBundleRequest {})
        .await
        .map_err(|e| AgentError::JoinFailed(format!("GetTrustBundle failed: {}", e)))?
        .into_inner();

    tracing::info!(
        svid_version = svid_resp.svid_version,
        "insecure join completed successfully"
    );

    Ok(())
}

#[cfg(feature = "production")]
pub async fn perform_insecure_join(
    _config: &AgentConfig,
    _storage: &Storage,
) -> Result<(), AgentError> {
    Err(AgentError::JoinFailed(
        "insecure join mode is compiled out of production builds".into(),
    ))
}
