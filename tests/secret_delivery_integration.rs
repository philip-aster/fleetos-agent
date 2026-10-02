// SPDX-License-Identifier: Apache-2.0
//! Phase 7.3: secret delivery pipeline (replay check → proto→core → X25519 unseal).

use fleetos_agent::secret::deliver::deliver_secret;
use fleetos_agent::storage::Storage;
use fleetos_core::crypto::{SecretSequence, seal};
use fleetos_core::proto::secret::SealedSecret as ProtoSealedSecret;

fn make_storage(name: &str) -> (Storage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    let storage = Storage::open(&path).expect("open storage");
    (storage, dir)
}

fn proto_sealed(
    target: &str,
    sealing_pubkey: &fleetos_core::crypto::RecipientX25519Pubkey,
    plaintext: &[u8],
    svid_version: u64,
    sequence: SecretSequence,
) -> ProtoSealedSecret {
    let sealed = seal(sealing_pubkey, plaintext, svid_version, sequence).expect("seal");
    ProtoSealedSecret {
        target_spiffe_id: target.to_string(),
        sealed_for_svid_version: sealed.sealed_for_svid_version,
        sequence: sealed.sequence.0,
        ephemeral_pubkey: sealed.ephemeral_pubkey.to_vec(),
        ciphertext: sealed.ciphertext.clone(),
    }
}

#[test]
fn deliver_secret_unseals_and_rejects_replay() {
    let (sealing_secret, sealing_pubkey) = fleetos_core::crypto::generate_sealing_keypair();
    let plaintext = b"super-secret-db-password".to_vec();
    let target = "spiffe://fleet.test.internal/ns/tenant-1/sa/db";
    let (storage, _dir) = make_storage("deliver");

    let sealed = proto_sealed(target, &sealing_pubkey, &plaintext, 7, SecretSequence(1));

    // First delivery succeeds and returns the exact plaintext.
    let recovered = deliver_secret(&storage, &sealed, &sealing_secret).expect("delivery");
    assert_eq!(recovered.as_slice(), plaintext.as_slice());

    // Replay with the same (target, svid_version, sequence) is rejected.
    assert!(deliver_secret(&storage, &sealed, &sealing_secret).is_err());

    // A strictly-newer sequence succeeds.
    let sealed2 = proto_sealed(target, &sealing_pubkey, &plaintext, 7, SecretSequence(2));
    let recovered2 = deliver_secret(&storage, &sealed2, &sealing_secret).expect("newer seq");
    assert_eq!(recovered2.as_slice(), plaintext.as_slice());
}

#[test]
fn deliver_secret_rejects_wrong_key() {
    let (_secret, sealing_pubkey) = fleetos_core::crypto::generate_sealing_keypair();
    let (other_secret, _) = fleetos_core::crypto::generate_sealing_keypair();
    let target = "spiffe://fleet.test.internal/ns/tenant-1/sa/db";
    let (storage, _dir) = make_storage("deliver_wrong_key");

    let sealed = proto_sealed(
        target,
        &sealing_pubkey,
        b"another-secret",
        1,
        SecretSequence(1),
    );

    // Unsealing with the wrong private key must fail (AEAD auth failure).
    assert!(deliver_secret(&storage, &sealed, &other_secret).is_err());
}
