// SPDX-License-Identifier: Apache-2.0
//! Replay-protection semantics for `SecretSequenceTracker` (S-10).
//!
//! Runs against a real fjall database in a temp directory so we exercise the
//! actual storage path, not a mock.

use fleetos_agent::identity::sequences;
use fleetos_agent::storage::Storage;

fn temp_storage(name: &str) -> (Storage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join(name);
    let storage = Storage::open(&path).expect("open storage");
    (storage, dir)
}

#[test]
fn first_secret_is_accepted() {
    let (storage, _dir) = temp_storage("first");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    let accepted = sequences::check_and_record(&storage, target, 1, 1).unwrap();
    assert!(accepted, "first secret with sequence 1 must be accepted");
}

#[test]
fn strictly_newer_sequence_is_accepted() {
    let (storage, _dir) = temp_storage("newer");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    assert!(sequences::check_and_record(&storage, target, 1, 1).unwrap());
    assert!(sequences::check_and_record(&storage, target, 1, 2).unwrap());
    assert!(sequences::check_and_record(&storage, target, 1, 5).unwrap());
}

#[test]
fn equal_sequence_is_rejected() {
    let (storage, _dir) = temp_storage("equal");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    assert!(sequences::check_and_record(&storage, target, 1, 3).unwrap());
    let replay = sequences::check_and_record(&storage, target, 1, 3).unwrap();
    assert!(!replay, "same sequence must be rejected as replay");
}

#[test]
fn older_sequence_is_rejected() {
    let (storage, _dir) = temp_storage("older");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    assert!(sequences::check_and_record(&storage, target, 1, 5).unwrap());
    let stale = sequences::check_and_record(&storage, target, 1, 2).unwrap();
    assert!(!stale, "older sequence must be rejected");
}

#[test]
fn sequence_zero_is_never_valid() {
    let (storage, _dir) = temp_storage("zero");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    let result = sequences::check_and_record(&storage, target, 1, 0).unwrap();
    assert!(!result, "sequence 0 must never be accepted");
}

#[test]
fn different_targets_are_independent() {
    let (storage, _dir) = temp_storage("targets");
    let target_a = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";
    let target_b = "spiffe://fleet.example.internal/ns/tenant-1/sa/web";

    assert!(sequences::check_and_record(&storage, target_a, 1, 10).unwrap());
    // target_b has no record, so sequence 1 is fine.
    assert!(sequences::check_and_record(&storage, target_b, 1, 1).unwrap());
    // target_a still rejects anything ≤ 10.
    assert!(!sequences::check_and_record(&storage, target_a, 1, 10).unwrap());
}

#[test]
fn different_svid_versions_are_independent() {
    let (storage, _dir) = temp_storage("versions");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    assert!(sequences::check_and_record(&storage, target, 1, 10).unwrap());
    // A new SVID version starts a fresh sequence space.
    assert!(sequences::check_and_record(&storage, target, 2, 1).unwrap());
    // Old version still enforces its own watermark.
    assert!(!sequences::check_and_record(&storage, target, 1, 5).unwrap());
}

#[test]
fn last_seen_tracks_watermark() {
    let (storage, _dir) = temp_storage("watermark");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    assert_eq!(sequences::last_seen(&storage, target, 1).unwrap(), None);

    sequences::check_and_record(&storage, target, 1, 4).unwrap();
    assert_eq!(sequences::last_seen(&storage, target, 1).unwrap(), Some(4));

    sequences::check_and_record(&storage, target, 1, 9).unwrap();
    assert_eq!(sequences::last_seen(&storage, target, 1).unwrap(), Some(9));
}

#[test]
fn state_survives_reopen() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join("reopen");

    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    {
        let storage = Storage::open(&path).expect("open");
        assert!(sequences::check_and_record(&storage, target, 1, 7).unwrap());
    }

    // Reopen the same database. The watermark must persist.
    {
        let storage = Storage::open(&path).expect("reopen");
        assert_eq!(sequences::last_seen(&storage, target, 1).unwrap(), Some(7));
        assert!(!sequences::check_and_record(&storage, target, 1, 7).unwrap());
        assert!(sequences::check_and_record(&storage, target, 1, 8).unwrap());
    }
}
