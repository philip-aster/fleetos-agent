// SPDX-License-Identifier: Apache-2.0
//! Phase 8.5.7: Delegation revocation tests.
//!
//! Verifies that a SagUpdate carrying revoked_delegation_ids removes the
//! matching key from the DelegatedKeyManager, and that non-matching IDs
//! leave the key intact.
use fleetos_agent::identity::degraded::DelegatedKeyManager;
use fleetos_core::spiffe::{DelegatedSigningKey, SpiffeId, WorkloadRole};

fn make_delegated_key(target: &SpiffeId) -> DelegatedSigningKey {
    let int_key = rcgen::KeyPair::generate().unwrap();
    let mut int_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, "Test Delegated Intermediate");
    int_params.distinguished_name = dn;
    int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    int_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let int_cert = int_params.self_signed(&int_key).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    DelegatedSigningKey {
        node_id: "spiffe://test.internal/ns/system/node/agent-1"
            .parse()
            .unwrap(),
        target_svid_id: target.clone(),
        target_ordinal: None,
        target_role: Some(WorkloadRole::try_from("replica").unwrap()),
        issued_at_unix: now,
        expires_at_unix: now + 14400,
        signing_key: zeroize::Zeroizing::new(int_key.serialize_der()),
        intermediate_cert_der: int_cert.der().to_vec(),
    }
}

#[test]
fn revoked_delegation_id_removes_key() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let mut mgr = DelegatedKeyManager::new();
    let key = make_delegated_key(&target);
    mgr.install_key(key, b"del-abc-123".to_vec());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(mgr.has_valid_key(&target, now));

    // Revoke with the matching delegation ID.
    let removed = mgr.remove_by_delegation_id(b"del-abc-123");
    assert_eq!(removed, Some(target.clone()));
    assert!(!mgr.has_valid_key(&target, now));
}

#[test]
fn non_matching_revocation_leaves_key_intact() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let mut mgr = DelegatedKeyManager::new();
    let key = make_delegated_key(&target);
    mgr.install_key(key, b"del-abc-123".to_vec());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(mgr.has_valid_key(&target, now));

    // Revoke with a NON-matching delegation ID.
    let removed = mgr.remove_by_delegation_id(b"del-xyz-999");
    assert_eq!(removed, None);
    assert!(mgr.has_valid_key(&target, now));
}

#[test]
fn multiple_keys_only_matching_one_removed() {
    let db: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let web: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/web".parse().unwrap();
    let mut mgr = DelegatedKeyManager::new();
    mgr.install_key(make_delegated_key(&db), b"del-1".to_vec());
    mgr.install_key(make_delegated_key(&web), b"del-2".to_vec());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(mgr.has_valid_key(&db, now));
    assert!(mgr.has_valid_key(&web, now));

    // Revoke only del-1.
    let removed = mgr.remove_by_delegation_id(b"del-1");
    assert_eq!(removed, Some(db.clone()));
    assert!(!mgr.has_valid_key(&db, now));
    assert!(mgr.has_valid_key(&web, now));
}
