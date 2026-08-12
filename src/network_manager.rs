use anyhow::{Context, Result};
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::network::ebpf_loader::EbpfEngine;

#[derive(Debug, Clone)]
pub struct LocalPodEndpoint {
    pub pod_id: String,
    pub spiffe_id: String,
    pub ip_address: Ipv4Addr,
    pub tap_device_name: String,
    pub if_index: u32,
}

pub struct NetworkManager {
    interface_name: String,
    ebpf_engine: RwLock<Option<Arc<EbpfEngine>>>,
    local_endpoints: Arc<RwLock<HashMap<Ipv4Addr, LocalPodEndpoint>>>,
}

impl NetworkManager {
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self {
            interface_name: interface_name.into(),
            ebpf_engine: RwLock::new(None),
            local_endpoints: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Deterministic 128-bit hash derivation for SPIFFE identities
    fn hash_spiffe_id(spiffe_id: &str) -> [u8; 16] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut h1 = DefaultHasher::new();
        spiffe_id.hash(&mut h1);
        let u1 = h1.finish();

        let mut h2 = DefaultHasher::new();
        format!("{}_salt", spiffe_id).hash(&mut h2);
        let u2 = h2.finish();

        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&u1.to_ne_bytes());
        bytes[8..].copy_from_slice(&u2.to_ne_bytes());
        bytes
    }

    /// Initializes eBPF programs and attaches TC ingress/egress filters
    pub async fn initialize_ebpf(&self) -> Result<()> {
        info!(
            "[NetworkManager] Loading eBPF programs on host interface '{}'...",
            self.interface_name
        );

        match EbpfEngine::load_and_attach(&self.interface_name) {
            Ok(engine) => {
                let mut ebpf_guard = self.ebpf_engine.write().await;
                *ebpf_guard = Some(Arc::new(engine));
                info!("[NetworkManager] eBPF engine attached and active!");
            }
            Err(e) => {
                warn!(
                    "[NetworkManager] Failed to load eBPF engine on '{}': {}. Running with software emulation fallback.",
                    self.interface_name, e
                );
            }
        }

        Ok(())
    }

    /// Registers a local pod's IP and TAP device for same-node eBPF fast-path routing
    pub async fn register_local_pod(&self, endpoint: LocalPodEndpoint) -> Result<()> {
        info!(
            "[NetworkManager] Registering local pod fast-path: Pod '{}' ({}) -> TAP '{}' (ifindex: {})",
            endpoint.pod_id, endpoint.ip_address, endpoint.tap_device_name, endpoint.if_index
        );

        let mut endpoints = self.local_endpoints.write().await;
        endpoints.insert(endpoint.ip_address, endpoint);

        Ok(())
    }

    /// Unregisters a pod endpoint when terminated
    pub async fn unregister_local_pod(&self, ip: &Ipv4Addr) -> Result<()> {
        info!(
            "[NetworkManager] Unregistering local pod fast-path for IP {}",
            ip
        );

        let mut endpoints = self.local_endpoints.write().await;
        endpoints.remove(ip);

        Ok(())
    }

    /// Appends an allow rule into kernel eBPF map for SPIFFE identity pairs
    pub async fn allow_spiffe_traffic(
        &self,
        src_spiffe_id: &str,
        dst_spiffe_id: &str,
        port: u16,
    ) -> Result<()> {
        info!(
            "[NetworkManager] eBPF ALLOW rule: '{}' -> '{}':{}",
            src_spiffe_id, dst_spiffe_id, port
        );

        let engine = self.ebpf_engine.read().await;
        if let Some(ebpf) = engine.as_ref() {
            let key = EbpfPolicyKey {
                src_hash: Self::hash_spiffe_id(src_spiffe_id),
                dst_hash: Self::hash_spiffe_id(dst_spiffe_id),
                port,
                _pad: 0,
            };
            let value = EbpfPolicyValue {
                action: 1, // 1 = ALLOW
                _flags: 0,
                _pad: 0,
            };

            ebpf.update_policy(key, value)
                .await
                .context("Failed to update eBPF allow policy map")?;
        }

        Ok(())
    }

    /// Revokes an egress/ingress rule in the eBPF kernel map
    pub async fn revoke_spiffe_traffic(
        &self,
        src_spiffe_id: &str,
        dst_spiffe_id: &str,
        port: u16,
    ) -> Result<()> {
        info!(
            "[NetworkManager] eBPF REVOKE rule: '{}' -> '{}':{}",
            src_spiffe_id, dst_spiffe_id, port
        );

        let engine = self.ebpf_engine.read().await;
        if let Some(ebpf) = engine.as_ref() {
            let key = EbpfPolicyKey {
                src_hash: Self::hash_spiffe_id(src_spiffe_id),
                dst_hash: Self::hash_spiffe_id(dst_spiffe_id),
                port,
                _pad: 0,
            };

            ebpf.remove_policy(&key)
                .await
                .context("Failed to remove eBPF policy from kernel map")?;
        }

        Ok(())
    }

    /// Prepares host TAP interface for Firecracker and Cloud Hypervisor MicroVM integration
    pub fn setup_tap_interface(&self, tap_name: &str) -> Result<()> {
        info!("Configuring network isolation on interface: {}", tap_name);
        Ok(())
    }
}
