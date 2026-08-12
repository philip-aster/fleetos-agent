//! FleetOS Host Agent (`fleetos-agent`)
//!
//! Bare-metal and microVM node daemon managing zero-trust eBPF networking,
//! Cloud Hypervisor pod runtimes, TPM hardware attestation, and local storage/VSOCK proxies.

pub mod attestation;
pub mod config;
pub mod eviction;
pub mod identity_sync;
pub mod metrics;
pub mod network;
pub mod network_manager;
pub mod pod;
pub mod probes;
pub mod runtime;
pub mod volume;
pub mod vsock;
pub mod workload_sync;

// Top-level re-exports for daemon startup
pub use attestation::BootAttestor;
pub use config::{AgentConfig, Cli};
pub use eviction::EvictionManager;
pub use identity_sync::IdentitySyncWorker;
pub use metrics::MetricsCollector;
pub use network::NetworkManager;
pub use runtime::{RuntimeManager, RuntimeSupervisor};
pub use volume::VolumeManager;
pub use vsock::VsockManager;
pub use workload_sync::WorkloadSyncWorker;
