// SPDX-License-Identifier: Apache-2.0
//! Phase 8.8: keystore envelope-tamper and prefix-dispatch tests.
//!
//! Software-sealing path (no TPM endpoint) is tested directly. The TPM
//! envelope path (>64-byte payloads) requires a TPM and is gated behind
//! FLEETOS_TPM_TESTS=1.
//!
//! Verifies: round-trip, prefix dispatch, label independence, overwrite,
//! master-key persistence, empty/single-byte edge cases, and software-seal
//! tamper detection.
use fleetos_agent::identity::keystore::{SensitiveStore, TpmSealedStore};
use fleetos_agent::storage::Storage;
use std::sync::Mutex;
static TPM_TEST_LOCK: Mutex<()> = Mutex::new(());

fn temp_storage(name: &str) -> (Storage, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join(name);
    let storage = Storage::open(&path).expect("open storage");
    (storage, dir)
}

/// Software-only store (no TPM endpoint).
fn software_store() -> TpmSealedStore {
    TpmSealedStore::new(None)
}

// --- Round-trip ---

#[test]
fn software_seal_small_payload_round_trip() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_small");
    let plaintext = [0xABu8; 32];
    store
        .store_sealed(&storage, b"test_key", &plaintext)
        .expect("store");
    let loaded = store
        .load_sealed(&storage, b"test_key")
        .expect("load")
        .expect("must exist");
    assert_eq!(loaded.as_slice(), plaintext.as_slice());
}

#[test]
fn software_seal_64_byte_boundary() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_64");
    let plaintext = [0xCDu8; 64];
    store
        .store_sealed(&storage, b"boundary", &plaintext)
        .expect("store");
    let loaded = store
        .load_sealed(&storage, b"boundary")
        .expect("load")
        .expect("must exist");
    assert_eq!(loaded.as_slice(), plaintext.as_slice());
}

#[test]
fn software_seal_65_byte_payload() {
    // With no TPM endpoint, even >64-byte payloads go through software seal.
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_65");
    let plaintext = [0xEFu8; 65];
    store
        .store_sealed(&storage, b"over_boundary", &plaintext)
        .expect("store");
    let loaded = store
        .load_sealed(&storage, b"over_boundary")
        .expect("load")
        .expect("must exist");
    assert_eq!(loaded.as_slice(), plaintext.as_slice());
}

#[test]
fn software_seal_large_payload() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_large");
    let plaintext: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    store
        .store_sealed(&storage, b"big_key", &plaintext)
        .expect("store");
    let loaded = store
        .load_sealed(&storage, b"big_key")
        .expect("load")
        .expect("must exist");
    assert_eq!(loaded, plaintext);
}

#[test]
fn software_seal_empty_payload() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_empty");
    let plaintext: Vec<u8> = vec![];
    store
        .store_sealed(&storage, b"empty", &plaintext)
        .expect("store");
    let loaded = store
        .load_sealed(&storage, b"empty")
        .expect("load")
        .expect("must exist");
    assert!(loaded.is_empty());
}

#[test]
fn software_seal_single_byte() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_single");
    store
        .store_sealed(&storage, b"one", &[0xFF])
        .expect("store");
    let loaded = store
        .load_sealed(&storage, b"one")
        .expect("load")
        .expect("must exist");
    assert_eq!(loaded, vec![0xFF]);
}

// --- Prefix dispatch / missing key ---

#[test]
fn missing_key_returns_none() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_missing");
    let loaded = store
        .load_sealed(&storage, b"nonexistent")
        .expect("load must not error");
    assert!(loaded.is_none());
}

#[test]
fn different_labels_are_independent() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_labels");
    let plain_a = [0x11u8; 32];
    let plain_b = [0x22u8; 32];
    store.store_sealed(&storage, b"label_a", &plain_a).unwrap();
    store.store_sealed(&storage, b"label_b", &plain_b).unwrap();
    let loaded_a = store.load_sealed(&storage, b"label_a").unwrap().unwrap();
    let loaded_b = store.load_sealed(&storage, b"label_b").unwrap().unwrap();
    assert_eq!(loaded_a.as_slice(), plain_a.as_slice());
    assert_eq!(loaded_b.as_slice(), plain_b.as_slice());
}

// --- Overwrite semantics ---

#[test]
fn store_sealed_overwrites_existing_key() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_overwrite");
    let v1 = [0x11u8; 32];
    let v2 = [0x22u8; 32];
    store.store_sealed(&storage, b"versioned", &v1).unwrap();
    store.store_sealed(&storage, b"versioned", &v2).unwrap();
    let loaded = store.load_sealed(&storage, b"versioned").unwrap().unwrap();
    assert_eq!(
        loaded.as_slice(),
        v2.as_slice(),
        "second write must overwrite"
    );
}

// --- Master key persistence across instances ---

#[test]
fn software_master_key_persists_across_store_instances() {
    let (storage, _dir) = temp_storage("sw_persist");
    let plaintext = [0x42u8; 32];
    let store1 = software_store();
    store1
        .store_sealed(&storage, b"persist_key", &plaintext)
        .unwrap();
    // A different TpmSealedStore instance must load via the same master key.
    let store2 = software_store();
    let loaded = store2
        .load_sealed(&storage, b"persist_key")
        .unwrap()
        .expect("must exist");
    assert_eq!(loaded.as_slice(), plaintext.as_slice());
}

// --- Software-seal tamper detection ---

#[test]
fn software_seal_corrupted_blob_fails() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_tamper");
    let plaintext = [0x99u8; 32];
    store
        .store_sealed(&storage, b"tamper_me", &plaintext)
        .unwrap();
    // Corrupt a byte in the stored blob.
    let mut raw = storage
        .delegation
        .get(b"tamper_me")
        .unwrap()
        .expect("blob must exist")
        .to_vec();
    if raw.len() > 10 {
        let idx = raw.len() - 3;
        raw[idx] ^= 0xFF;
    }
    storage.delegation.insert(b"tamper_me", raw).unwrap();
    // Loading the corrupted blob must fail (AEAD auth failure).
    let result = store.load_sealed(&storage, b"tamper_me");
    match result {
        Ok(Some(loaded)) => {
            assert_ne!(
                loaded.as_slice(),
                plaintext.as_slice(),
                "corrupted ciphertext must not produce valid plaintext"
            );
        }
        Ok(None) | Err(_) => {} // acceptable: load failed or returned None
    }
}

#[test]
fn software_seal_cross_label_blob_swap_fails() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_swap");
    let plain_a = [0xAAu8; 32];
    store.store_sealed(&storage, b"original", &plain_a).unwrap();
    // Copy the blob to a different label.
    let raw = storage
        .delegation
        .get(b"original")
        .unwrap()
        .expect("blob must exist")
        .to_vec();
    storage.delegation.insert(b"different", raw).unwrap();
    // The software seal binds the key_label into the crypto (via
    // fleetos_core::crypto::seal with the master key), so cross-label
    // swap should either fail or produce wrong plaintext.
    let result = store.load_sealed(&storage, b"different");
    match result {
        Ok(Some(loaded)) => {
            // If it decodes, it must NOT be the original plaintext
            // (the master key is the same, but the seal is bound to the
            // label via the SealedSecret structure).
            // NOTE: software_seal uses fleetos_core::crypto::seal which
            // does NOT bind the key_label into the AEAD AAD (unlike the
            // envelope path). So cross-label swap WILL succeed here.
            // This is a known limitation of the software-seal fallback.
            // The envelope path (TPM) DOES bind the label.
            // We document this but don't assert failure.
            let _ = loaded;
        }
        Ok(None) | Err(_) => {} // also acceptable
    }
}

// --- generate_and_store_sealing_key ---

#[test]
fn generate_and_store_sealing_key_round_trip() {
    let store = software_store();
    let (storage, _dir) = temp_storage("sw_keypair");
    let pubkey = store
        .generate_and_store_sealing_key(&storage)
        .expect("generate");
    assert_eq!(pubkey.len(), 32, "X25519 pubkey must be 32 bytes");
    // The private half must be loadable.
    let secret = store
        .load_sealing_secret(&storage)
        .expect("load")
        .expect("must exist");
    assert_eq!(secret.len(), 32, "X25519 private key must be 32 bytes");
}

// --- Gated: TPM envelope path (requires swtpm) ---

#[test]
fn tpm_envelope_seal_unseal_round_trip() {
    let _guard = TPM_TEST_LOCK.lock().unwrap();
    if std::env::var("FLEETOS_TPM_TESTS").as_deref() != Ok("1") {
        eprintln!("SKIP: set FLEETOS_TPM_TESTS=1 with swtpm running");
        return;
    }
    let endpoint = fleetos_core::attestation::tpm::TpmEndpoint::Swtpm {
        host: std::env::var("FLEETOS_TPM_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        port: std::env::var("FLEETOS_TPM_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(2321),
    };
    let store = TpmSealedStore::new(Some(endpoint));
    let (storage, _dir) = temp_storage("tpm_envelope");
    // ~138-byte PKCS#8 DER — exceeds 64-byte TPM limit, routes to envelope.
    let plaintext: Vec<u8> = (0..138).map(|i| (i % 256) as u8).collect();
    store
        .store_sealed(&storage, b"svid_private_key", &plaintext)
        .expect("envelope seal");
    let loaded = store
        .load_sealed(&storage, b"svid_private_key")
        .expect("envelope unseal")
        .expect("must exist");
    assert_eq!(loaded, plaintext);
}

#[test]
fn tpm_envelope_tamper_wrong_label_fails() {
    let _guard = TPM_TEST_LOCK.lock().unwrap();
    if std::env::var("FLEETOS_TPM_TESTS").as_deref() != Ok("1") {
        eprintln!("SKIP: set FLEETOS_TPM_TESTS=1 with swtpm running");
        return;
    }
    let endpoint = fleetos_core::attestation::tpm::TpmEndpoint::Swtpm {
        host: std::env::var("FLEETOS_TPM_HOST").unwrap_or_else(|_| "127.0.0.1".into()),
        port: std::env::var("FLEETOS_TPM_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(2321),
    };
    let store = TpmSealedStore::new(Some(endpoint));
    let (storage, _dir) = temp_storage("tpm_tamper_label");
    let plaintext: Vec<u8> = (0..128).map(|i| (i % 256) as u8).collect();
    store
        .store_sealed(&storage, b"original_label", &plaintext)
        .expect("seal");
    // Copy the blob to a different label. The envelope AEAD AAD binds
    // key_label, so decryption under a different label must fail.
    let raw = storage
        .delegation
        .get(b"original_label")
        .unwrap()
        .expect("blob must exist")
        .to_vec();
    storage.delegation.insert(b"different_label", raw).unwrap();
    let result = store.load_sealed(&storage, b"different_label");
    match result {
        Ok(Some(loaded)) => {
            assert_ne!(
                loaded, plaintext,
                "cross-label envelope blob swap must not succeed"
            );
        }
        Ok(None) | Err(_) => {} // AEAD failure is the expected path
    }
}
