// SPDX-License-Identifier: Apache-2.0
//! CR-10 secure join flow: TPM credential activation.
//!
//! Flow:
//!   1. Generate X25519 sealing keypair (TPM-sealed)
//!   2. Open TPM attestation session via TpmContextManager (EK + AK)
//!   3. RequestActivation → receive MakeCredential challenge
//!   4. ActivateCredential → recover secret S
//!   5. Compute activation proof (HMAC of server nonce with S)
//!   6. Quote server nonce with selected PCRs
//!   7. Generate node SVID keypair + CSR
//!   8. SubmitActivationProof → receive signed SVID
//!   9. Install SVID into storage
//!
//! CORE-WI-3: All TPM operations go through a single TpmContextManager.
//! This avoids the TPM_RC_MEMORY failure that occurred when AttestationSession
//! held EK+AK (2 slots) while seal_to_pcr needed an SRK (3rd slot) on swtpm.
use crate::client::channels::build_server_trust_channel;
use crate::client::retry::{RetryAction, classify_error};
use crate::config::AgentConfig;
use crate::error::AgentError;
use crate::identity::keystore::{SensitiveStore, TpmSealedStore};
use crate::identity::svid;
use crate::storage::Storage;
use fleetos_core::attestation::compute_activation_proof;
use fleetos_core::attestation::tpm::TpmContextManager;
use fleetos_core::proto::identity::CaServiceClient;
use fleetos_core::proto::identity::{
    ActivationProof, ActivationRequest, AttestationServiceClient, TrustBundleRequest,
};
use fleetos_core::spiffe::{IdKind, SpiffeId};

pub async fn perform_secure_join(
    config: &AgentConfig,
    storage: &Storage,
) -> Result<(), AgentError> {
    tracing::info!("starting secure join flow (CR-10)");

    let tpm_endpoint = config.tpm_endpoint();
    let sealed_store = TpmSealedStore::new(Some(tpm_endpoint.clone()));

    // 1. Generate and store X25519 sealing keypair
    let sealing_pubkey_bytes = sealed_store.generate_and_store_sealing_key(storage)?;
    let sealing_pubkey = fleetos_core::crypto::RecipientX25519Pubkey(sealing_pubkey_bytes);

    // 2. Open TPM attestation session via TpmContextManager (CORE-WI-3).
    //    The manager coordinates transient slot usage: on swtpm, EK and AK
    //    contexts are saved immediately after creation, freeing all slots
    //    for subsequent operations like seal_to_pcr.
    let mut tpm_manager = TpmContextManager::new(&tpm_endpoint)
        .map_err(|e| AgentError::Attestation(format!("TPM context manager init failed: {}", e)))?;
    let mut session = tpm_manager
        .begin_attestation()
        .map_err(|e| AgentError::Attestation(format!("TPM attestation session failed: {}", e)))?;

    // CORE-WI-3: ak_pub()/ek_pub() return &[u8] directly (no Result).
    let ak_pub = session.ak_pub().to_vec();
    let ek_pub = session.ek_pub().to_vec();

    // Read EK certificate if available (for EK chain validation by control).
    let ek_cert_der = tpm_manager
        .read_ek_cert()
        .map_err(|e| AgentError::Attestation(format!("read EK cert failed: {}", e)))?
        .unwrap_or_default();

    // 3. Build node SPIFFE ID
    let node_spiffe_id = SpiffeId::new(
        &config.node.trust_domain,
        "system",
        IdKind::Node,
        &config.node.name,
    );

    // 4. Connect to control plane (server-trust TLS for join leg)
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

    // 5. RequestActivation with redirect-and-retry
    let challenge = loop {
        let req = ActivationRequest {
            ak_pub: ak_pub.clone(),
            ek_cert_der: ek_cert_der.clone(),
            ek_pub: ek_pub.clone(),
        };
        match att_client.request_activation(req).await {
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
                        "RequestActivation failed: {}",
                        reason
                    )));
                }
            },
        }
    };

    // 6. Activate credential via the manager (CORE-WI-3).
    //    The manager loads EK+AK from saved contexts, performs the
    //    activation, then saves them back — freeing slots for seal_to_pcr.
    let secret_bytes = tpm_manager
        .activate(&mut session, &challenge.credential_blob, &challenge.secret)
        .map_err(|e| AgentError::Attestation(format!("activate failed: {}", e)))?;
    let secret: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| AgentError::Attestation("secret is not 32 bytes".into()))?;

    // 7. Compute activation proof
    let hmac = compute_activation_proof(&secret, &challenge.server_nonce);

    // 8. Generate quote via the manager (CORE-WI-3).
    let quote_out = tpm_manager
        .quote(
            &mut session,
            &challenge.server_nonce,
            &config.join.pcr_indices,
        )
        .map_err(|e| AgentError::Attestation(format!("quote failed: {}", e)))?;

    // 9. Generate node SVID keypair and CSR.
    //    CORE-WI-3: seal_to_pcr now goes through the same TpmContextManager,
    //    so it can proceed even while the attestation session is active.
    let svid_keypair = rcgen::KeyPair::generate()
        .map_err(|e| AgentError::Attestation(format!("rcgen keygen failed: {}", e)))?;
    let svid_priv_der = svid_keypair.serialize_der();
    sealed_store.store_sealed(storage, b"svid_private_key", &svid_priv_der)?;
    let csr = fleetos_core::spiffe::ca::build_csr(&node_spiffe_id, &svid_keypair)
        .map_err(|e| AgentError::Attestation(format!("build_csr failed: {}", e)))?;

    // 10. SubmitActivationProof with redirect-and-retry
    let svid_resp = loop {
        let proof = ActivationProof {
            hmac: hmac.to_vec(),
            quote: quote_out.quote.clone(),
            quote_signature: quote_out.signature.clone(),
            pcr_selection: postcard::to_allocvec(&quote_out.pcr_values)
                .map_err(AgentError::Serialization)?,
            csr_der: csr.der.clone(),
            agent_x25519_pubkey: sealing_pubkey.0.to_vec(),
        };
        match att_client.submit_activation_proof(proof).await {
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
                        "SubmitActivationProof failed: {}",
                        reason
                    )));
                }
            },
        }
    };

    // 11. Install SVID
    let current_gen = svid::load(storage)?.generation;
    svid::store(
        storage,
        &[svid_resp.cert_chain_der],
        svid_resp.svid_version,
        current_gen,
    )?;

    // 12. GetTrustBundle (fetch latest from control)
    let _bundle = ca_client
        .get_trust_bundle(TrustBundleRequest {})
        .await
        .map_err(|e| AgentError::JoinFailed(format!("GetTrustBundle failed: {}", e)))?
        .into_inner();

    // 13. Clean up the attestation session (CORE-WI-3).
    tpm_manager
        .finish_attestation(session)
        .map_err(|e| AgentError::Attestation(format!("finish attestation failed: {}", e)))?;

    tracing::info!(
        svid_version = svid_resp.svid_version,
        "secure join completed successfully"
    );
    Ok(())
}
