// SPDX-License-Identifier: Apache-2.0
//! Phase 7.5 integration test: degraded-mode delegated signing.
//!
//! Verifies the map-based DelegatedKeyManager: install, validity, refresh
//! timing, and that renew_svid_locally produces a valid cert with the correct
//! SPIFFE ID, degraded=true extension, and role/ordinal from the key scope.
use fleetos_agent::identity::degraded::{DelegatedKeyManager, now_unix};
use fleetos_core::spiffe::{DelegatedSigningKey, SpiffeId, WorkloadRole};
use std::time::Duration;

/// Build a valid delegated signing key scoped to `target` with the given
/// role/ordinal. Uses a self-signed intermediate CA (pathLen=0).
fn make_delegated_key(target: &SpiffeId, role: &str, ordinal: Option<u32>) -> DelegatedSigningKey {
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
    let int_cert_der = int_cert.der().to_vec();

    let now = now_unix();
    DelegatedSigningKey {
        node_id: "spiffe://test.internal/ns/system/node/agent-1"
            .parse()
            .unwrap(),
        target_svid_id: target.clone(),
        target_ordinal: ordinal,
        target_role: Some(WorkloadRole::try_from(role).unwrap()),
        issued_at_unix: now,
        expires_at_unix: now + 14400,
        signing_key: zeroize::Zeroizing::new(int_key.serialize_der()),
        intermediate_cert_der: int_cert_der,
    }
}

#[test]
fn install_and_validity() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let key = make_delegated_key(&target, "replica", Some(2));
    let mut mgr = DelegatedKeyManager::new();
    mgr.install_key(key, b"del-1".to_vec());

    let now = now_unix();
    assert!(mgr.has_valid_key(&target, now));
    // Just installed: 0% elapsed, no refresh needed.
    assert!(!mgr.should_refresh(&target, now));
    assert!(mgr.remaining_ttl_secs(&target, now) > 0);

    // Unknown target has no key.
    let other: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/web".parse().unwrap();
    assert!(!mgr.has_valid_key(&other, now));
}

#[test]
fn should_refresh_at_75_percent() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let mut key = make_delegated_key(&target, "replica", Some(2));
    let now = now_unix();
    let ttl = 14400u64;
    // Backdate so 80% of the TTL has elapsed (> 75% threshold).
    key.issued_at_unix = now - (ttl * 80 / 100);
    key.expires_at_unix = key.issued_at_unix + ttl;

    let mut mgr = DelegatedKeyManager::new();
    mgr.install_key(key, b"del-1".to_vec());
    assert!(mgr.should_refresh(&target, now));
    assert!(mgr.keys_needing_refresh(now).contains(&target));
}

#[test]
fn renew_svid_locally_produces_valid_cert() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let key = make_delegated_key(&target, "replica", Some(2));
    let mut mgr = DelegatedKeyManager::new();
    mgr.install_key(key, b"del-1".to_vec());

    let now = now_unix();
    let workload_key = rcgen::KeyPair::generate().unwrap();
    let csr = fleetos_core::spiffe::ca::build_csr(&target, &workload_key).unwrap();
    let cert_der = mgr
        .renew_svid_locally(&target, &csr.der, Duration::from_secs(3600), now)
        .unwrap();

    // Correct SPIFFE ID.
    let spiffe_id = fleetos_core::spiffe::extract_spiffe_id(&cert_der).unwrap();
    assert_eq!(spiffe_id, target);

    // Degraded marker present.
    assert!(fleetos_core::spiffe::is_degraded(&cert_der));

    // Role/ordinal stamped from the key scope.
    let role = fleetos_core::spiffe::extract_role(&cert_der).unwrap();
    assert_eq!(role.as_str(), "replica");
    assert_eq!(fleetos_core::spiffe::extract_ordinal(&cert_der), Some(2));
}

#[test]
fn renew_fails_closed_without_key() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let mgr = DelegatedKeyManager::new();
    let workload_key = rcgen::KeyPair::generate().unwrap();
    let csr = fleetos_core::spiffe::ca::build_csr(&target, &workload_key).unwrap();
    let result = mgr.renew_svid_locally(&target, &csr.der, Duration::from_secs(3600), now_unix());
    assert!(result.is_err());
}

#[test]
fn expired_key_is_not_returned() {
    let target: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let mut key = make_delegated_key(&target, "replica", Some(2));
    let now = now_unix();
    // Force expiry into the past.
    key.expires_at_unix = now - 1;
    let mut mgr = DelegatedKeyManager::new();
    mgr.install_key(key, b"del-1".to_vec());

    assert!(!mgr.has_valid_key(&target, now));
    assert!(mgr.get_key(&target, now).is_none());
    mgr.prune_expired(now);
    assert!(mgr.targets().is_empty());
}

#[test]
fn map_holds_multiple_targets() {
    let db: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/db".parse().unwrap();
    let web: SpiffeId = "spiffe://test.internal/ns/tenant-1/sa/web".parse().unwrap();
    let mut mgr = DelegatedKeyManager::new();
    mgr.install_key(make_delegated_key(&db, "replica", Some(0)), b"d1".to_vec());
    mgr.install_key(make_delegated_key(&web, "primary", None), b"d2".to_vec());

    let now = now_unix();
    assert!(mgr.has_valid_key(&db, now));
    assert!(mgr.has_valid_key(&web, now));
    assert_eq!(mgr.targets().len(), 2);
}
