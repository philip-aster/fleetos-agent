// SPDX-License-Identifier: Apache-2.0
//! Phase 8.8: config.rs parsing and validation tests.
//!
//! Covers TOML deserialization, structural validation (empty fields, range
//! checks), default application, join_token_path resolution, mode-dependent
//! sealing endpoint selection, and TPM backend mapping.
//!
//! Pure file-based tests — no gRPC, no eBPF, no storage beyond tempdir.
use fleetos_agent::config::{AgentConfig, JoinMode, TpmBackend};
use fleetos_core::attestation::tpm::TpmEndpoint;
use std::path::Path;

/// Minimal valid config TOML.
fn minimal_config_toml() -> &'static str {
    r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "secure"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#
}

/// Write TOML to a temp file and load it.
fn load_config(dir: &Path, toml_str: &str) -> AgentConfig {
    let path = dir.join("agent.toml");
    std::fs::write(&path, toml_str).expect("write config");
    AgentConfig::load(&path).expect("config must parse and validate")
}

fn load_config_err(dir: &Path, toml_str: &str) -> String {
    let path = dir.join("agent.toml");
    std::fs::write(&path, toml_str).expect("write config");
    AgentConfig::load(&path)
        .expect_err("config must fail validation")
        .to_string()
}

// --- Full parse ---

#[test]
fn full_valid_config_parses() {
    let dir = tempfile::tempdir().unwrap();
    let config = load_config(dir.path(), minimal_config_toml());
    assert_eq!(config.node.name, "agent-1");
    assert_eq!(config.node.trust_domain, "fleet.test.internal");
    assert_eq!(config.control.address, "10.0.1.1:9443");
    assert_eq!(config.join.mode, JoinMode::Secure);
}

// --- Defaults ---

#[test]
fn defaults_applied_when_omitted() {
    let dir = tempfile::tempdir().unwrap();
    let config = load_config(dir.path(), minimal_config_toml());
    // [node]
    assert_eq!(config.node.heartbeat_interval_secs, 30);
    // [join]
    assert_eq!(config.join.pcr_indices, vec![0, 7, 9]);
    assert!(config.join.token.is_empty());
    assert!(config.join.join_token_path.is_none());
    // [tpm]
    assert_eq!(config.tpm.backend, TpmBackend::Device);
    assert_eq!(config.tpm.device_path, "/dev/tpmrm0");
    assert_eq!(config.tpm.host, "localhost");
    assert_eq!(config.tpm.port, 2321);
    // [ebpf]
    assert_eq!(
        config.ebpf.object_path,
        std::path::PathBuf::from("/usr/lib/fleetos/fleetos-ebpf")
    );
    assert_eq!(config.ebpf.map_headroom_percent, 20);
    // [svid]
    assert_eq!(config.svid.ttl_secs, 3600);
    assert!((config.svid.refresh_fraction - 0.75).abs() < f64::EPSILON);
    assert_eq!(config.svid.workload_ttl_secs, 3600);
    assert_eq!(config.svid.delegated_key_ttl_secs, 14400);
    // [vsock_attest]
    assert_eq!(config.vsock_attest.port, 0x4649);
    // [images]
    assert_eq!(
        config.images.cache_path,
        std::path::PathBuf::from("/var/lib/fleetos/images")
    );
    // [networking]
    assert_eq!(config.networking.workload_ip_cidr, "172.30.0.0/16");
    // [observability]
    assert!(config.observability.otlp_endpoint.is_empty());
    assert_eq!(config.observability.push_interval_secs, 5);
}

// --- Validation: empty required fields ---

#[test]
fn empty_node_name_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = minimal_config_toml().replace("agent-1", "");
    let err = load_config_err(dir.path(), &toml);
    assert!(
        err.contains("node.name"),
        "error must mention node.name: {err}"
    );
}

#[test]
fn empty_trust_domain_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = minimal_config_toml().replace("fleet.test.internal", "");
    let err = load_config_err(dir.path(), &toml);
    assert!(err.contains("trust_domain"), "{err}");
}

#[test]
fn empty_control_address_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = minimal_config_toml().replace("10.0.1.1:9443", "");
    let err = load_config_err(dir.path(), &toml);
    assert!(err.contains("control.address"), "{err}");
}

// --- Validation: range checks ---

#[test]
fn refresh_fraction_zero_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[svid]\nrefresh_fraction = 0.0\n",
        minimal_config_toml()
    );
    let err = load_config_err(dir.path(), &toml);
    assert!(err.contains("refresh_fraction"), "{err}");
}

#[test]
fn refresh_fraction_one_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[svid]\nrefresh_fraction = 1.0\n",
        minimal_config_toml()
    );
    let err = load_config_err(dir.path(), &toml);
    assert!(err.contains("refresh_fraction"), "{err}");
}

#[test]
fn refresh_fraction_negative_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[svid]\nrefresh_fraction = -0.5\n",
        minimal_config_toml()
    );
    let err = load_config_err(dir.path(), &toml);
    assert!(err.contains("refresh_fraction"), "{err}");
}

#[test]
fn map_headroom_over_100_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[ebpf]\nmap_headroom_percent = 150\n",
        minimal_config_toml()
    );
    let err = load_config_err(dir.path(), &toml);
    assert!(err.contains("map_headroom_percent"), "{err}");
}

// --- Validation: insecure mode requires token ---

#[test]
fn insecure_mode_without_token_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "insecure"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#;
    let err = load_config_err(dir.path(), toml);
    assert!(err.contains("join.token"), "{err}");
}

#[test]
fn insecure_mode_with_token_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "insecure"
token = "test-join-token-12345"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#;
    let config = load_config(dir.path(), toml);
    assert_eq!(config.join.mode, JoinMode::Insecure);
    assert_eq!(config.join.token, "test-join-token-12345");
}

// --- join_token_path resolution ---

#[test]
fn join_token_path_resolves_token_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("join-token");
    std::fs::write(&token_path, "file-based-token-abc\n").unwrap();
    let toml = format!(
        r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "insecure"
join_token_path = "{}"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#,
        token_path.display()
    );
    let config = load_config(dir.path(), &toml);
    assert_eq!(config.join.token, "file-based-token-abc");
}

#[test]
fn join_token_path_precedence_over_inline_token() {
    let dir = tempfile::tempdir().unwrap();
    let token_path = dir.path().join("join-token");
    std::fs::write(&token_path, "from-file\n").unwrap();
    let toml = format!(
        r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "insecure"
token = "inline-token"
join_token_path = "{}"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#,
        token_path.display()
    );
    let config = load_config(dir.path(), &toml);
    assert_eq!(config.join.token, "from-file", "file must take precedence");
}

#[test]
fn join_token_path_missing_file_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "insecure"
join_token_path = "/nonexistent/path/token"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#;
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, toml).unwrap();
    assert!(AgentConfig::load(&path).is_err());
}

// --- sealing_endpoint mode selection ---

#[test]
fn sealing_endpoint_none_for_insecure() {
    let dir = tempfile::tempdir().unwrap();
    let toml = r#"
[node]
name = "agent-1"
trust_domain = "fleet.test.internal"

[control]
address = "10.0.1.1:9443"
trust_bundle_path = "/etc/fleetos/dc-trust-bundle.pem"

[join]
mode = "insecure"
token = "tok"

[storage]
fjall_path = "/var/lib/fleetos/agent_db"
"#;
    let config = load_config(dir.path(), toml);
    assert!(config.sealing_endpoint().is_none());
}

#[test]
fn sealing_endpoint_some_for_secure() {
    let dir = tempfile::tempdir().unwrap();
    let config = load_config(dir.path(), minimal_config_toml());
    assert!(config.sealing_endpoint().is_some());
}

// --- tpm_endpoint backend mapping ---

#[test]
fn tpm_endpoint_device_backend() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[tpm]\nbackend = \"device\"\ndevice_path = \"/dev/custom-tpm\"\n",
        minimal_config_toml()
    );
    let config = load_config(dir.path(), &toml);
    match config.tpm_endpoint() {
        TpmEndpoint::Device { path } => assert_eq!(path, "/dev/custom-tpm"),
        other => panic!("expected Device, got {:?}", other),
    }
}

#[test]
fn tpm_endpoint_swtpm_backend() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[tpm]\nbackend = \"swtpm\"\nhost = \"127.0.0.1\"\nport = 2321\n",
        minimal_config_toml()
    );
    let config = load_config(dir.path(), &toml);
    match config.tpm_endpoint() {
        TpmEndpoint::Swtpm { host, port } => {
            assert_eq!(host, "127.0.0.1");
            assert_eq!(port, 2321);
        }
        other => panic!("expected Swtpm, got {:?}", other),
    }
}

#[test]
fn tpm_endpoint_mssim_backend() {
    let dir = tempfile::tempdir().unwrap();
    let toml = format!(
        "{}\n[tpm]\nbackend = \"mssim\"\nhost = \"localhost\"\nport = 2322\n",
        minimal_config_toml()
    );
    let config = load_config(dir.path(), &toml);
    match config.tpm_endpoint() {
        TpmEndpoint::Mssim { host, port } => {
            assert_eq!(host, "localhost");
            assert_eq!(port, 2322);
        }
        other => panic!("expected Mssim, got {:?}", other),
    }
}

// --- Malformed TOML ---

#[test]
fn missing_config_file_rejected() {
    let result = AgentConfig::load(Path::new("/nonexistent/agent.toml"));
    assert!(result.is_err());
}

#[test]
fn invalid_toml_syntax_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, "this is not valid toml [[[").unwrap();
    assert!(AgentConfig::load(&path).is_err());
}
