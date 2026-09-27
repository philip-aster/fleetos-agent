// SPDX-License-Identifier: Apache-2.0
//! Integration test: secure join flow (TPM 2.0 credential activation, CR-10)
//! against the mock control plane, full crypto via swtpm.
//!
//! Prerequisites (same recipe as fleetos-core / fleetos-control):
//!
//!   pkill swtpm; rm -rf /tmp/fleetos-tpmstate; mkdir -p /tmp/fleetos-tpmstate
//!   swtpm socket --tpm2 \
//!     --tpmstate dir=/tmp/fleetos-tpmstate \
//!     --ctrl type=tcp,port=2322 --server type=tcp,port=2321 \
//!     --flags startup-clear --log level=0 &
//!
//!   FLEETOS_TPM_TESTS=1 FLEETOS_TPM_BACKEND=swtpm \
//!     cargo test --features production --test join_secure -- --nocapture
#![cfg(feature = "production")]

mod common;

use common::mock_control::{MockConfig, spawn_mock_control_plane};
use fleetos_agent::config::AgentConfig;
use fleetos_agent::identity::keystore::TpmSealedStore;
use fleetos_agent::identity::svid;
use fleetos_agent::storage::Storage;

/// Resolve the swtpm endpoint, or None to skip (matches the fleetos-core
/// FLEETOS_TPM_TESTS convention).
fn swtpm_endpoint() -> Option<fleetos_core::attestation::tpm::TpmEndpoint> {
    if std::env::var("FLEETOS_TPM_TESTS").unwrap_or_default() != "1" {
        eprintln!("SKIP: set FLEETOS_TPM_TESTS=1 (with swtpm running) to run TPM tests");
        return None;
    }
    match std::env::var("FLEETOS_TPM_BACKEND").as_deref() {
        // FIX: TpmEndpoint is an enum with struct variants, not a constructor function
        Ok("swtpm") => Some(fleetos_core::attestation::tpm::TpmEndpoint::Swtpm {
            host: "127.0.0.1".to_string(),
            port: 2321,
        }),
        other => {
            eprintln!("SKIP: FLEETOS_TPM_BACKEND={other:?}, only \"swtpm\" is supported here");
            None
        }
    }
}

#[tokio::test]
async fn secure_join_end_to_end() {
    let Some(endpoint) = swtpm_endpoint() else {
        return;
    };

    let temp = tempfile::tempdir().expect("tempdir");

    // Mock control plane in secure mode: it performs TPM2_MakeCredential
    // against the same swtpm instance the agent uses.
    let mock = spawn_mock_control_plane(MockConfig {
        join_token: None,
        trust_domain: "fleet.test.internal".to_string(),
        tpm_endpoint: Some(endpoint),
    })
    .await
    .expect("mock control plane");

    let trust_bundle_path = temp.path().join("trust-bundle.pem");
    std::fs::write(&trust_bundle_path, &mock.ca_pem).unwrap();

    let config_toml = format!(
        r#"
[node]
name = "test-node"
tenant = "test-tenant"
trust_domain = "fleet.test.internal"

[control]
address = "{address}"
trust_bundle_path = "{trust_bundle}"

[join]
mode = "secure"

[tpm]
backend = "swtpm"
endpoint = "tcp://127.0.0.1:2321"

[storage]
fjall_path = "{db}"
"#,
        address = mock.address,
        trust_bundle = trust_bundle_path.display(),
        db = temp.path().join("db").display(),
    );
    let config_path = temp.path().join("agent.toml");
    std::fs::write(&config_path, config_toml).unwrap();
    let config = AgentConfig::load(&config_path).expect("agent config");

    // Storage + sealing keypair (mirrors main.rs ordering).
    let storage = Storage::open(&config.storage.fjall_path).expect("storage");
    let keystore = TpmSealedStore::new(Some(config.tpm_endpoint()));
    keystore
        .generate_and_store_sealing_key(&storage)
        .expect("sealing keypair");

    // Perform the secure join: RequestActivation → ActivateCredential →
    // HMAC proof + PCR quote + CSR → SubmitActivationProof → SvidResponse.
    fleetos_agent::join::secure::perform_secure_join(&config, &storage)
        .await
        .expect("secure join");

    // SvidState must be persisted with the mock-signed chain.
    let state = svid::load(&storage).expect("svid load");
    assert!(!state.is_none(), "SvidState must be persisted after join");
    assert_eq!(state.svid_version, 1, "first SVID version must be 1");
    assert!(
        !state.cert_chain_der.is_empty() && !state.cert_chain_der[0].is_empty(),
        "cert chain must be present"
    );
}
