// SPDX-License-Identifier: Apache-2.0
//! Wire protocol round-trip tests for the VSOCK attestation handshake.
//!
//! Locks the postcard layout from the agent side, mirroring the tests in
//! `fleetos-guest-init/src/protocol.rs`. Uses `frame_msg`/`decode_msg`
//! from `fleetos_core::vsock_proto` to verify the framing contract.

use fleetos_core::vsock_proto::*;

/// Round-trip a message through frame_msg/decode_msg.
fn round_trip<T>(msg: &T) -> T
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let framed = frame_msg(msg).unwrap();
    let len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
    assert_eq!(framed.len(), 4 + len);
    decode_msg(&framed[4..]).unwrap()
}

#[test]
fn challenge_round_trip() {
    let c = VsockAttestationChallenge {
        protocol_version: PROTOCOL_VERSION,
        nonce: [0xAB; 32],
    };
    let back: VsockAttestationChallenge = round_trip(&c);
    assert_eq!(back.nonce, c.nonce);
    assert_eq!(back.protocol_version, c.protocol_version);
}

#[test]
fn proof_round_trip() {
    let p = VsockAttestationProof {
        quote_type: QUOTE_TYPE_TPM2,
        raw_quote: vec![1, 2, 3, 4],
        guest_x25519_pubkey: [0x11; 32],
    };
    let back: VsockAttestationProof = round_trip(&p);
    assert_eq!(back.quote_type, p.quote_type);
    assert_eq!(back.raw_quote, p.raw_quote);
    assert_eq!(back.guest_x25519_pubkey, p.guest_x25519_pubkey);
}

#[test]
fn result_round_trip() {
    let r = AgentAttestResult {
        accepted: true,
        reason: String::new(),
    };
    let back: AgentAttestResult = round_trip(&r);
    assert_eq!(back.accepted, r.accepted);
    assert_eq!(back.reason, r.reason);
}

#[test]
fn config_round_trip() {
    let c = WorkloadConfig {
        svid_cert_chain_der: vec![vec![0x30, 0x82]],
        svid_private_key_der: vec![0x04, 0x20],
        env_vars: vec![("FOO".to_string(), "bar".to_string())],
        volume_mounts: vec![VolumeMountConfig {
            name: "scratch".to_string(),
            mount_path: "/scratch".to_string(),
            read_only: false,
        }],
        dummy_ip_routes: vec![DummyIpRouteConfig {
            dummy_ip: [240, 0, 0, 45],
            service: "db".to_string(),
            role: "replica".to_string(),
            tenant: "acme".to_string(),
        }],
        workload_binary_path: "/usr/bin/app".to_string(),
        workload_args: vec!["--serve".to_string()],
        trust_domain: "fleet.example.internal".to_string(),
        tenant_id: "acme".to_string(),
        service_name: "db".to_string(),
        role: "replica".to_string(),
        guest_ip: [10, 0, 0, 2],
        netmask: [255, 255, 255, 0],
        gateway: [10, 0, 0, 1],
    };
    let back: WorkloadConfig = round_trip(&c);
    assert_eq!(back.workload_binary_path, c.workload_binary_path);
    assert_eq!(back.dummy_ip_routes[0].dummy_ip, [240, 0, 0, 45]);
    assert_eq!(back.guest_ip, [10, 0, 0, 2]);
    assert_eq!(back.trust_domain, c.trust_domain);
}

#[test]
fn all_quote_type_constants_are_distinct() {
    let types = [
        QUOTE_TYPE_TPM2,
        QUOTE_TYPE_SEV_SNP,
        QUOTE_TYPE_TDX,
        QUOTE_TYPE_HOST_MEASURED,
        QUOTE_TYPE_DEV_SOFTWARE,
    ];
    for i in 0..types.len() {
        for j in (i + 1)..types.len() {
            assert_ne!(types[i], types[j], "quote types must be distinct");
        }
    }
}

#[test]
fn protocol_version_is_1() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn max_message_size_is_16mib() {
    assert_eq!(MAX_MESSAGE_BYTES, 16 * 1024 * 1024);
}

#[test]
fn host_cid_is_2() {
    assert_eq!(HOST_CID, 2);
}

#[test]
fn vsock_port_is_0x4649() {
    assert_eq!(VSOCK_PORT, 0x4649);
}
