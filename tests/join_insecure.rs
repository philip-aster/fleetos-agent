// SPDX-License-Identifier: Apache-2.0
//! Integration test: insecure join flow (join-token) against the mock control
//! plane. Real TLS throughout — build_server_trust_channel is fully exercised.
//!
//! Non-production only: the R-1 fence compiles insecure join out under the
//! `production` feature.
#![cfg(not(feature = "production"))]

mod common;

use common::mock_control::{MockConfig, spawn_mock_control_plane};
use fleetos_agent::config::AgentConfig;
use fleetos_agent::error::AgentError;
use fleetos_agent::identity::keystore::TpmSealedStore;
use fleetos_agent::identity::svid;
use fleetos_agent::storage::Storage;

/// Build config + storage + sealing keypair against a running mock. Mirrors
/// main.rs ordering: config → storage → sealing keypair → join.
async fn setup(
    file_token: &str,
    mock_token: Option<&str>,
) -> (tempfile::TempDir, AgentConfig, Storage) {
    let temp = tempfile::tempdir().expect("tempdir");

    let join_token_path = temp.path().join("join-token");
    std::fs::write(&join_token_path, file_token).unwrap();

    let mock = spawn_mock_control_plane(MockConfig {
        join_token: mock_token.map(|t| t.to_string()),
        trust_domain: "fleet.test.internal".to_string(),
        tpm_endpoint: None,
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
mode = "insecure"
join_token_path = "{join_token}"

[storage]
fjall_path = "{db}"
"#,
        address = mock.address,
        trust_bundle = trust_bundle_path.display(),
        join_token = join_token_path.display(),
        db = temp.path().join("db").display(),
    );
    let config_path = temp.path().join("agent.toml");
    std::fs::write(&config_path, config_toml).unwrap();
    let config = AgentConfig::load(&config_path).expect("agent config");

    let storage = Storage::open(&config.storage.fjall_path).expect("storage");
    // Insecure mode: software-only sealing, no TPM involvement.
    let keystore = TpmSealedStore::new(None);
    keystore
        .generate_and_store_sealing_key(&storage)
        .expect("sealing keypair");

    (temp, config, storage)
}

#[tokio::test]
async fn insecure_join_end_to_end() {
    let (_temp, config, storage) =
        setup("test-join-token-12345", Some("test-join-token-12345")).await;

    fleetos_agent::join::insecure::perform_insecure_join(&config, &storage)
        .await
        .expect("insecure join");

    // SvidState must be persisted with the mock-signed chain.
    let state = svid::load(&storage).expect("svid load");
    assert!(!state.is_none(), "SvidState must be persisted after join");
    assert_eq!(state.svid_version, 1, "first SVID version must be 1");
    assert!(
        !state.cert_chain_der.is_empty() && !state.cert_chain_der[0].is_empty(),
        "cert chain must be present"
    );
}

#[tokio::test]
async fn insecure_join_rejects_bad_token() {
    // File holds a different token than the mock expects.
    let (_temp, config, storage) = setup("wrong-token", Some("correct-token")).await;

    let err = fleetos_agent::join::insecure::perform_insecure_join(&config, &storage)
        .await
        .expect_err("join with bad token must fail");
    assert!(
        matches!(err, AgentError::JoinFailed(_)),
        "expected JoinFailed, got: {err}"
    );
}

#[tokio::test]
async fn insecure_join_token_is_single_use() {
    let temp = tempfile::tempdir().expect("tempdir");
    let join_token_path = temp.path().join("join-token");
    std::fs::write(&join_token_path, "single-use-token").unwrap();

    let mock = spawn_mock_control_plane(MockConfig {
        join_token: Some("single-use-token".to_string()),
        trust_domain: "fleet.test.internal".to_string(),
        tpm_endpoint: None,
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
mode = "insecure"
join_token_path = "{join_token}"

[storage]
fjall_path = "{db}"
"#,
        address = mock.address,
        trust_bundle = trust_bundle_path.display(),
        join_token = join_token_path.display(),
        db = temp.path().join("db").display(),
    );
    let config_path = temp.path().join("agent.toml");
    std::fs::write(&config_path, config_toml).unwrap();
    let config = AgentConfig::load(&config_path).expect("agent config");

    let storage = Storage::open(&config.storage.fjall_path).expect("storage");
    // Insecure mode: software-only sealing, no TPM involvement.
    let keystore = TpmSealedStore::new(None);
    keystore
        .generate_and_store_sealing_key(&storage)
        .expect("sealing keypair");

    // First join succeeds and consumes the token.
    fleetos_agent::join::insecure::perform_insecure_join(&config, &storage)
        .await
        .expect("first join");

    // Second join with the same token must be rejected (single-use).
    let err = fleetos_agent::join::insecure::perform_insecure_join(&config, &storage)
        .await
        .expect_err("second join with consumed token must fail");
    assert!(
        matches!(err, AgentError::JoinFailed(_)),
        "expected JoinFailed, got: {err}"
    );
}
