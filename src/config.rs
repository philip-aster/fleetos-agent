// SPDX-License-Identifier: Apache-2.0
//! Agent configuration, loaded from TOML.
//!
//! Structure mirrors `agent.example.toml`. Validation is structural only
//! (empty fields, range checks). Mode-specific warnings (R-1 insecure fence)
//! are emitted by `main.rs` after the tracing subscriber is initialized.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Top-level agent configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AgentConfig {
    /// Identity of this agent node.
    pub node: NodeConfig,
    /// Control plane connection.
    pub control: ControlConfig,
    /// Join configuration.
    #[serde(default)]
    pub join: JoinConfig,
    /// TPM backend configuration.
    #[serde(default)]
    pub tpm: TpmConfig,
    /// Storage configuration.
    pub storage: StorageConfig,
    /// eBPF configuration.
    #[serde(default)]
    pub ebpf: EbpfConfig,
    /// SVID lifecycle configuration.
    #[serde(default)]
    pub svid: SvidConfig,
    /// VSOCK attestation server configuration (for MicroVM guest attestation).
    #[serde(default)]
    pub vsock_attest: VsockAttestConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// Human-readable name for this agent node.
    pub name: String,
    /// SPIFFE trust domain for the Data/Control overlay.
    pub trust_domain: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlConfig {
    /// Data/Control address of the control plane.
    pub address: String,
    /// Path to the PEM file holding the Data/Control root bundle.
    pub trust_bundle_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct JoinConfig {
    /// "secure" = TPM credential activation (CR-10). Production.
    /// "insecure" = join-token only, structural quote checks. TESTING ONLY.
    #[serde(default = "default_join_mode")]
    pub mode: JoinMode,
    /// For insecure mode only: single-use join token.
    #[serde(default)]
    pub token: String,
    /// Path to the trust bundle for the attestation TLS leg.
    #[serde(default)]
    pub trust_bundle_path: Option<PathBuf>,
    /// PCR indices to quote during attestation.
    #[serde(default = "default_pcr_indices")]
    pub pcr_indices: Vec<u8>,
}

impl Default for JoinConfig {
    fn default() -> Self {
        Self {
            mode: default_join_mode(),
            token: String::new(),
            trust_bundle_path: None,
            pcr_indices: default_pcr_indices(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JoinMode {
    Secure,
    Insecure,
}

fn default_join_mode() -> JoinMode {
    JoinMode::Secure
}

fn default_pcr_indices() -> Vec<u8> {
    vec![0, 7, 9]
}

#[derive(Debug, Clone, Deserialize)]
pub struct TpmConfig {
    /// Backend: "device" (hardware, default), "swtpm", or "mssim".
    #[serde(default = "default_tpm_backend")]
    pub backend: TpmBackend,
    /// Device path for the "device" backend.
    #[serde(default = "default_tpm_device_path")]
    pub device_path: String,
    /// Host for the "swtpm"/"mssim" backends.
    #[serde(default = "default_tpm_host")]
    pub host: String,
    /// Port for the "swtpm"/"mssim" backends.
    #[serde(default = "default_tpm_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TpmBackend {
    /// Hardware TPM via the kernel resource manager.
    Device,
    /// Software TPM (`swtpm`) over a TCP socket.
    Swtpm,
    /// Microsoft TPM simulator over a TCP socket.
    Mssim,
}

fn default_tpm_backend() -> TpmBackend {
    TpmBackend::Device
}

fn default_tpm_device_path() -> String {
    "/dev/tpmrm0".to_owned()
}

fn default_tpm_host() -> String {
    "localhost".to_owned()
}

fn default_tpm_port() -> u16 {
    2321
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            backend: default_tpm_backend(),
            device_path: default_tpm_device_path(),
            host: default_tpm_host(),
            port: default_tpm_port(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    /// Path to the fjall database directory. Local disk only.
    pub fjall_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EbpfConfig {
    /// Path to the compiled eBPF object (AA-8).
    #[serde(default = "default_ebpf_object_path")]
    pub object_path: PathBuf,
    /// Cgroup v2 mount point for cgroup_sock_addr and sock_ops attachment.
    #[serde(default = "default_cgroup_path")]
    pub cgroup_path: PathBuf,
    /// BPF filesystem pin path for map pinning.
    #[serde(default = "default_pin_path")]
    pub pin_path: PathBuf,
    /// Percentage of headroom to add when sizing maps at load time (Ruling C).
    #[serde(default = "default_map_headroom")]
    pub map_headroom_percent: u32,
    /// Network interfaces to attach TC programs to (for Cloud Hypervisor TAP devices).
    #[serde(default)]
    pub interfaces: Vec<String>,
}

fn default_ebpf_object_path() -> PathBuf {
    PathBuf::from("/usr/lib/fleetos/fleetos-ebpf")
}

fn default_cgroup_path() -> PathBuf {
    PathBuf::from("/sys/fs/cgroup")
}

fn default_pin_path() -> PathBuf {
    PathBuf::from("/sys/fs/bpf/fleetos")
}

fn default_map_headroom() -> u32 {
    20
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            object_path: default_ebpf_object_path(),
            cgroup_path: default_cgroup_path(),
            pin_path: default_pin_path(),
            map_headroom_percent: default_map_headroom(),
            interfaces: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SvidConfig {
    /// SVID TTL in seconds.
    #[serde(default = "default_svid_ttl_secs")]
    pub ttl_secs: u64,
    /// Fraction of TTL at which refresh is triggered. Default 0.75 (75%).
    #[serde(default = "default_refresh_fraction")]
    pub refresh_fraction: f64,
}

fn default_svid_ttl_secs() -> u64 {
    3600
}

fn default_refresh_fraction() -> f64 {
    0.75
}

impl Default for SvidConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_svid_ttl_secs(),
            refresh_fraction: default_refresh_fraction(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct VsockAttestConfig {
    /// VSOCK port for the attestation server.
    /// Default 0x4649 per fleetos_core::vsock_proto::VSOCK_PORT.
    #[serde(default = "default_vsock_port")]
    pub port: u32,
    /// Path to the kernel image for host-measured attestation (EBPF-CR-3).
    #[serde(default)]
    pub kernel_path: Option<PathBuf>,
    /// Path to the erofs rootfs for host-measured attestation.
    #[serde(default)]
    pub rootfs_path: Option<PathBuf>,
    /// Path to the fleetos-guest-init binary for host-measured attestation.
    #[serde(default)]
    pub guest_init_path: Option<PathBuf>,
}

fn default_vsock_port() -> u32 {
    0x4649
}

impl Default for VsockAttestConfig {
    fn default() -> Self {
        Self {
            port: default_vsock_port(),
            kernel_path: None,
            rootfs_path: None,
            guest_init_path: None,
        }
    }
}

impl AgentConfig {
    /// Load configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, crate::error::AgentError> {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            crate::error::AgentError::Config(format!("failed to read config: {}", e))
        })?;
        let config: AgentConfig = toml::from_str(&raw).map_err(|e| {
            crate::error::AgentError::Config(format!("failed to parse config: {}", e))
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Structural validation. Mode-specific warnings are emitted by main.rs
    /// after the tracing subscriber is initialized.
    pub fn validate(&self) -> Result<(), crate::error::AgentError> {
        if self.node.name.is_empty() {
            return Err(crate::error::AgentError::Config(
                "node.name cannot be empty".to_owned(),
            ));
        }
        if self.node.trust_domain.is_empty() {
            return Err(crate::error::AgentError::Config(
                "node.trust_domain cannot be empty".to_owned(),
            ));
        }
        if self.control.address.is_empty() {
            return Err(crate::error::AgentError::Config(
                "control.address cannot be empty".to_owned(),
            ));
        }

        // SVID refresh fraction must be in (0.0, 1.0).
        if self.svid.refresh_fraction <= 0.0 || self.svid.refresh_fraction >= 1.0 {
            return Err(crate::error::AgentError::Config(format!(
                "svid.refresh_fraction must be in (0.0, 1.0), got {}",
                self.svid.refresh_fraction
            )));
        }

        // eBPF headroom must be <= 100%.
        if self.ebpf.map_headroom_percent > 100 {
            return Err(crate::error::AgentError::Config(format!(
                "ebpf.map_headroom_percent must be <= 100, got {}",
                self.ebpf.map_headroom_percent
            )));
        }

        // Insecure mode requires a join token.
        if self.join.mode == JoinMode::Insecure && self.join.token.is_empty() {
            return Err(crate::error::AgentError::Config(
                "join.token is required when join.mode = \"insecure\"".to_owned(),
            ));
        }

        Ok(())
    }

    /// Convert agent TPM config to fleetos-core's TpmEndpoint.
    pub fn tpm_endpoint(&self) -> fleetos_core::attestation::tpm::TpmEndpoint {
        match self.tpm.backend {
            TpmBackend::Device => fleetos_core::attestation::tpm::TpmEndpoint::Device {
                path: self.tpm.device_path.clone(),
            },
            TpmBackend::Swtpm => fleetos_core::attestation::tpm::TpmEndpoint::Swtpm {
                host: self.tpm.host.clone(),
                port: self.tpm.port,
            },
            TpmBackend::Mssim => fleetos_core::attestation::tpm::TpmEndpoint::Mssim {
                host: self.tpm.host.clone(),
                port: self.tpm.port,
            },
        }
    }
}
