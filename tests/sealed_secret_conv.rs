// SPDX-License-Identifier: Apache-2.0
//! Conversion round-trip and replay rejection tests for secret delivery.
//!
//! Pure computation tests — no network, no TPM, no storage.
//! Verifies proto→core conversion and replay semantics.

use fleetos_agent::secret::deliver::proto_to_core;
use fleetos_core::crypto::SecretSequence;
use fleetos_core::proto::secret::SealedSecret as ProtoSealedSecret;

fn make_proto_secret(
    target: &str,
    svid_version: u64,
    sequence: u64,
    ephemeral: [u8; 32],
    ciphertext: Vec<u8>,
) -> ProtoSealedSecret {
    ProtoSealedSecret {
        target_spiffe_id: target.to_string(),
        sealed_for_svid_version: svid_version,
        sequence,
        ephemeral_pubkey: ephemeral.to_vec(),
        ciphertext,
    }
}

#[test]
fn proto_to_core_round_trip() {
    let ephemeral = [0xAB; 32];
    let ciphertext = vec![1, 2, 3, 4, 5];
    let proto = make_proto_secret(
        "spiffe://fleet.example.internal/ns/tenant-1/sa/db",
        42,
        7,
        ephemeral,
        ciphertext.clone(),
    );

    let core = proto_to_core(&proto).unwrap();

    assert_eq!(core.sealed_for_svid_version, 42);
    assert_eq!(core.sequence, SecretSequence(7));
    assert_eq!(core.ephemeral_pubkey, ephemeral);
    assert_eq!(core.ciphertext, ciphertext);
}

#[test]
fn proto_to_core_rejects_bad_ephemeral_length() {
    let proto = ProtoSealedSecret {
        target_spiffe_id: "spiffe://test/ns/t/sa/s".to_string(),
        sealed_for_svid_version: 1,
        sequence: 1,
        ephemeral_pubkey: vec![0; 16], // wrong length
        ciphertext: vec![],
    };

    let result = proto_to_core(&proto);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn proto_to_core_accepts_empty_ciphertext() {
    // Empty ciphertext is structurally valid (unseal will fail, but
    // conversion should succeed).
    let proto = make_proto_secret("spiffe://test/ns/t/sa/s", 1, 1, [0; 32], vec![]);

    let core = proto_to_core(&proto).unwrap();
    assert!(core.ciphertext.is_empty());
}

#[test]
fn sequence_is_preserved() {
    let proto = make_proto_secret("spiffe://test/ns/t/sa/s", 5, 99, [0; 32], vec![1]);
    let core = proto_to_core(&proto).unwrap();
    assert_eq!(core.sequence.0, 99);
}

#[test]
fn svid_version_is_preserved() {
    let proto = make_proto_secret("spiffe://test/ns/t/sa/s", 12345, 1, [0; 32], vec![1]);
    let core = proto_to_core(&proto).unwrap();
    assert_eq!(core.sealed_for_svid_version, 12345);
}

// --- Replay rejection tests (using storage) ---

use fleetos_agent::identity::sequences;
use fleetos_agent::storage::Storage;

fn temp_storage(name: &str) -> (Storage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join(name);
    let storage = Storage::open(&path).expect("open storage");
    (storage, dir)
}

#[test]
fn replay_rejection_via_deliver_pipeline() {
    // Simulate the sequence check that deliver_secret performs.
    let (storage, _dir) = temp_storage("deliver_replay");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    // First delivery at sequence 1: accepted.
    assert!(sequences::check_and_record(&storage, target, 1, 1).unwrap());

    // Replay at sequence 1: rejected.
    assert!(!sequences::check_and_record(&storage, target, 1, 1).unwrap());

    // Newer sequence 2: accepted.
    assert!(sequences::check_and_record(&storage, target, 1, 2).unwrap());

    // Stale sequence 1 after seeing 2: rejected.
    assert!(!sequences::check_and_record(&storage, target, 1, 1).unwrap());
}

#[test]
fn different_svid_versions_are_independent_sequences() {
    let (storage, _dir) = temp_storage("deliver_versions");
    let target = "spiffe://fleet.example.internal/ns/tenant-1/sa/db";

    // SVID version 1, sequence 5.
    assert!(sequences::check_and_record(&storage, target, 1, 5).unwrap());

    // SVID version 2, sequence 1: independent, accepted.
    assert!(sequences::check_and_record(&storage, target, 2, 1).unwrap());

    // SVID version 1, sequence 3: stale, rejected.
    assert!(!sequences::check_and_record(&storage, target, 1, 3).unwrap());
}
