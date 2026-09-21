// SPDX-License-Identifier: Apache-2.0
//! Tests for the policy sync diff logic.
//!
//! Pure computation tests — no eBPF, no gRPC, no storage.
//! Verifies the desired-state diff, version monotonicity, and fail-closed
//! behavior on empty policy.

use fleetos_agent::policy::sync::{
    PolicySyncState, apply_mutations_to_state, compile_and_sync, compute_sync_mutations,
};
use fleetos_policy_compiler::{CompiledPolicyEntry, CompiledPolicySet};

/// Helper: create an exact-tier compiled entry.
fn make_exact(
    src: u8,
    dst: u8,
    proto: u8,
    port: u16,
    decision: u8,
    version: u64,
) -> CompiledPolicyEntry {
    CompiledPolicyEntry::Exact {
        src_fingerprint: [src; 16],
        dst_fingerprint: [dst; 16],
        protocol: proto,
        dst_port: port,
        decision,
        sag_version: version,
    }
}

/// Helper: create a wildcard-tier compiled entry.
fn make_wildcard(src: u8, dst: u8, decision: u8, version: u64) -> CompiledPolicyEntry {
    CompiledPolicyEntry::Wildcard {
        src_fingerprint: [src; 16],
        dst_fingerprint: [dst; 16],
        decision,
        sag_version: version,
    }
}

/// Helper: build a CompiledPolicySet from entries.
fn make_set(version: u64, entries: Vec<CompiledPolicyEntry>) -> CompiledPolicySet {
    let wildcard_count = entries
        .iter()
        .filter(|e| matches!(e, CompiledPolicyEntry::Wildcard { .. }))
        .count();
    let exact_count = entries
        .iter()
        .filter(|e| matches!(e, CompiledPolicyEntry::Exact { .. }))
        .count();
    CompiledPolicySet {
        version,
        entries,
        wildcard_count,
        exact_count,
    }
}

// --- Basic diff tests ---

#[test]
fn empty_state_all_inserted() {
    let state = PolicySyncState::new();
    let compiled = make_set(
        1,
        vec![make_exact(1, 2, 6, 80, 1, 1), make_wildcard(3, 4, 0, 1)],
    );

    let mutations = compute_sync_mutations(&state, &compiled);

    assert_eq!(mutations.insert_exact.len(), 1);
    assert_eq!(mutations.insert_wildcard.len(), 1);
    assert_eq!(mutations.delete_exact.len(), 0);
    assert_eq!(mutations.delete_wildcard.len(), 0);
}

#[test]
fn same_entries_no_mutations() {
    let compiled = make_set(
        1,
        vec![make_exact(1, 2, 6, 80, 1, 1), make_wildcard(3, 4, 0, 1)],
    );

    // Build state as if we already applied this set.
    let mut state = PolicySyncState::new();
    let mutations = compute_sync_mutations(&state, &compiled);
    apply_mutations_to_state(&mut state, &mutations, 1);

    // Now sync the same set again.
    let mutations2 = compute_sync_mutations(&state, &compiled);
    assert!(mutations2.is_empty());
}

#[test]
fn new_entries_inserted_old_deleted() {
    let compiled_v1 = make_set(
        1,
        vec![make_exact(1, 2, 6, 80, 1, 1), make_wildcard(3, 4, 0, 1)],
    );

    let mut state = PolicySyncState::new();
    let mutations = compute_sync_mutations(&state, &compiled_v1);
    apply_mutations_to_state(&mut state, &mutations, 1);

    // V2: remove the wildcard, add a new exact.
    let compiled_v2 = make_set(
        2,
        vec![
            make_exact(1, 2, 6, 80, 1, 2),   // same key, new version
            make_exact(5, 6, 17, 443, 1, 2), // new key
        ],
    );

    let mutations2 = compute_sync_mutations(&state, &compiled_v2);

    // The wildcard should be deleted.
    assert_eq!(mutations2.delete_wildcard.len(), 1);
    // The new exact should be inserted.
    assert_eq!(mutations2.insert_exact.len(), 1);
    // The existing exact should NOT be re-inserted (same key).
    assert_eq!(mutations2.insert_exact.len(), 1);
    assert_eq!(mutations2.delete_exact.len(), 0);
}

#[test]
fn empty_policy_deletes_all() {
    // Fail-closed: an empty policy set means default-deny. All entries deleted.
    let compiled_v1 = make_set(
        1,
        vec![
            make_exact(1, 2, 6, 80, 1, 1),
            make_wildcard(3, 4, 0, 1),
            make_exact(5, 6, 17, 443, 1, 1),
        ],
    );

    let mut state = PolicySyncState::new();
    let mutations = compute_sync_mutations(&state, &compiled_v1);
    apply_mutations_to_state(&mut state, &mutations, 1);

    // V2: empty policy.
    let compiled_v2 = make_set(2, vec![]);
    let mutations2 = compute_sync_mutations(&state, &compiled_v2);

    assert_eq!(mutations2.delete_exact.len(), 2);
    assert_eq!(mutations2.delete_wildcard.len(), 1);
    assert_eq!(mutations2.insert_exact.len(), 0);
    assert_eq!(mutations2.insert_wildcard.len(), 0);
}

// --- Version monotonicity tests ---

#[test]
fn stale_version_discarded() {
    let state = PolicySyncState {
        current_version: 10,
        exact_keys: std::collections::HashSet::new(),
        wildcard_keys: std::collections::HashSet::new(),
    };

    let result = compile_and_sync(&state, &[], 5, "fleet.example.internal").unwrap();
    assert!(result.is_none(), "stale version must be discarded");

    let result = compile_and_sync(&state, &[], 10, "fleet.example.internal").unwrap();
    assert!(result.is_none(), "equal version must be discarded");
}

#[test]
fn newer_version_accepted() {
    let state = PolicySyncState {
        current_version: 5,
        exact_keys: std::collections::HashSet::new(),
        wildcard_keys: std::collections::HashSet::new(),
    };

    let result = compile_and_sync(&state, &[], 6, "fleet.example.internal").unwrap();
    assert!(result.is_some(), "newer version must be accepted");
}

// --- State tracking tests ---

#[test]
fn apply_mutations_updates_state() {
    let mut state = PolicySyncState::new();
    let compiled = make_set(
        1,
        vec![make_exact(1, 2, 6, 80, 1, 1), make_wildcard(3, 4, 0, 1)],
    );

    let mutations = compute_sync_mutations(&state, &compiled);
    apply_mutations_to_state(&mut state, &mutations, 1);

    assert_eq!(state.current_version, 1);
    assert_eq!(state.exact_keys.len(), 1);
    assert_eq!(state.wildcard_keys.len(), 1);
}

#[test]
fn multiple_syncs_converge() {
    let mut state = PolicySyncState::new();

    // V1: two entries.
    let v1 = make_set(
        1,
        vec![make_exact(1, 2, 6, 80, 1, 1), make_wildcard(3, 4, 0, 1)],
    );
    let m1 = compute_sync_mutations(&state, &v1);
    apply_mutations_to_state(&mut state, &m1, 1);
    assert_eq!(state.exact_keys.len(), 1);
    assert_eq!(state.wildcard_keys.len(), 1);

    // V2: replace wildcard with a different exact.
    let v2 = make_set(
        2,
        vec![
            make_exact(1, 2, 6, 80, 1, 2),
            make_exact(7, 8, 6, 8080, 1, 2),
        ],
    );
    let m2 = compute_sync_mutations(&state, &v2);
    apply_mutations_to_state(&mut state, &m2, 2);
    assert_eq!(state.exact_keys.len(), 2);
    assert_eq!(state.wildcard_keys.len(), 0);

    // V3: back to the original set.
    let v3 = make_set(
        3,
        vec![make_exact(1, 2, 6, 80, 1, 3), make_wildcard(3, 4, 0, 3)],
    );
    let m3 = compute_sync_mutations(&state, &v3);
    apply_mutations_to_state(&mut state, &m3, 3);
    assert_eq!(state.exact_keys.len(), 1);
    assert_eq!(state.wildcard_keys.len(), 1);
}
