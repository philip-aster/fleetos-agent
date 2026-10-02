// SPDX-License-Identifier: Apache-2.0
//! Integration test: SAG → policy sync pipeline (Phase 7.1)
//!
//! Verifies that compile_and_sync produces correct PolicyMutations
//! from a SagUpdate with exact and wildcard rules, and that stale
//! frames are discarded.
use fleetos_agent::policy::sync::{PolicySyncState, compile_and_sync};
use fleetos_core::proto::fleetos::{PeerSelector, SagRule as ProtoSagRule};

/// Build a proto SagRule matching the actual state.proto schema.
/// SagRule has: id, from (PeerSelector), to (PeerSelector), action (i32).
/// PeerSelector has: tenant, service_name, role, port (optional uint32).
fn proto_rule(service: &str, tenant: &str) -> ProtoSagRule {
    ProtoSagRule {
        id: String::new(), // advisory, ignored by proto_rule_to_core
        from: Some(PeerSelector {
            tenant: tenant.to_string(),
            service_name: service.to_string(),
            role: String::new(),
            port: None,
        }),
        to: Some(PeerSelector {
            tenant: tenant.to_string(),
            service_name: service.to_string(),
            role: String::new(),
            port: None,
        }),
        action: 0, // SagRule.Action::ALLOW = 0
    }
}

#[test]
fn compile_and_sync_produces_mutations_for_wildcard_rules() {
    let state = PolicySyncState::new();
    let rules = vec![proto_rule("billing", "prod"), proto_rule("auth", "prod")];
    let result = compile_and_sync(&state, &rules, 1, "fleetos.internal")
        .expect("compile_and_sync should succeed");
    assert!(result.is_some(), "non-stale frame should produce mutations");
    let (mutations, compiled) = result.unwrap();
    // Both rules have port: None → wildcard tier.
    assert_eq!(
        mutations.insert_wildcard.len(),
        2,
        "expected 2 wildcard insertions"
    );
    assert!(mutations.insert_exact.is_empty(), "no exact rules");
    assert_eq!(compiled.entries.len(), 2);
}

#[test]
fn compile_and_sync_discards_stale_frames() {
    let state = PolicySyncState {
        current_version: 5,
        exact_keys: std::collections::HashSet::new(),
        wildcard_keys: std::collections::HashSet::new(),
    };
    let rules = vec![proto_rule("billing", "prod")];
    // Version 3 ≤ current 5 → stale, should return None.
    let result = compile_and_sync(&state, &rules, 3, "fleetos.internal")
        .expect("compile_and_sync should succeed");
    assert!(
        result.is_none(),
        "stale frame (version 3 ≤ 5) should be discarded"
    );
    // Version 5 ≤ current 5 → stale, should return None.
    let result = compile_and_sync(&state, &rules, 5, "fleetos.internal")
        .expect("compile_and_sync should succeed");
    assert!(
        result.is_none(),
        "stale frame (version 5 ≤ 5) should be discarded"
    );
    // Version 6 > current 5 → fresh, should produce mutations.
    let result = compile_and_sync(&state, &rules, 6, "fleetos.internal")
        .expect("compile_and_sync should succeed");
    assert!(
        result.is_some(),
        "fresh frame (version 6 > 5) should produce mutations"
    );
}

#[test]
fn policy_sync_state_version_advances_after_apply() {
    use fleetos_agent::policy::sync::apply_mutations_to_state;
    let mut state = PolicySyncState::new();
    assert_eq!(state.current_version, 0);
    let rules = vec![proto_rule("billing", "prod")];
    let result = compile_and_sync(&state, &rules, 7, "fleetos.internal")
        .expect("compile_and_sync should succeed")
        .expect("non-stale frame should produce mutations");
    let (mutations, _) = result;
    apply_mutations_to_state(&mut state, &mutations, 7);
    assert_eq!(state.current_version, 7, "version should advance to 7");
    assert_eq!(
        state.wildcard_keys.len(),
        1,
        "one wildcard key should be tracked"
    );
}
