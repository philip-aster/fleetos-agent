pub mod ebpf_loader;
pub mod veth_tap;

use anyhow::{Context, Result};
use ebpf_loader::EbpfEngine;
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

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
    ebpf_engine: Arc<Mutex<Option<EbpfEngine>>>,
    /// In-memory table of local workloads running on this host
    local_pods: Arc<RwLock<HashMap<Ipv4Addr, LocalPodEndpoint>>>,
    /// Interface index of the local TAP connection to fleetos-router
    router_tap_if_index: Arc<Mutex<Option<u32>>>,
}

impl NetworkManager {
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self {
            interface_name: interface_name.into(),
            ebpf_engine: Arc::new(Mutex::new(None)),
            local_pods: Arc::new(RwLock::new(HashMap::new())),
            router_tap_if_index: Arc::new(Mutex::new(None)),
        }
    }

    /// Truncates a BLAKE3 hash of a SPIFFE ID string to 16 bytes for eBPF kernel matching
    pub fn hash_spiffe_id(spiffe_id: &str) -> [u8; 16] {
        let hash = blake3::hash(spiffe_id.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash.as_bytes()[..16]);
        bytes
    }

    /// Sets the host interface index pointing to the local fleetos-router instance
    pub async fn set_router_tap_index(&self, if_index: u32) {
        let mut guard = self.router_tap_if_index.lock().await;
        *guard = Some(if_index);
        info!("Set local router egress interface index to {}", if_index);
    }

    /// Registers a newly booted local Pod into the local fast-path table
    pub async fn register_local_pod(&self, endpoint: LocalPodEndpoint) -> Result<()> {
        info!(
            "Registering local pod fast-path: Pod '{}' ({}) -> TAP '{}' (ifindex {})",
            endpoint.pod_id, endpoint.ip_address, endpoint.tap_device_name, endpoint.if_index
        );

        let mut pods = self.local_pods.write().await;
        pods.insert(endpoint.ip_address, endpoint.clone());

        // Update local redirection map in eBPF kernel if engine is ready
        let guard = self.ebpf_engine.lock().await;
        if let Some(engine) = guard.as_ref() {
            // Populate kernel DEVMAP / Redirect Map for same-node TAP-to-TAP redirection
            engine
                .register_local_redirect(endpoint.ip_address, endpoint.if_index)
                .await?;
        }

        Ok(())
    }

    /// Unregisters a terminated local Pod from the kernel fast-path
    pub async fn unregister_local_pod(&self, ip_address: &Ipv4Addr) -> Result<()> {
        info!("Unregistering local pod fast-path for IP: {}", ip_address);

        let mut pods = self.local_pods.write().await;
        pods.remove(ip_address);

        let guard = self.ebpf_engine.lock().await;
        if let Some(engine) = guard.as_ref() {
            engine.remove_local_redirect(ip_address).await?;
        }

        Ok(())
    }

    /// Fast-path check: Is target IP co-located on this physical host?
    pub async fn is_local_ip(&self, ip_address: &Ipv4Addr) -> bool {
        let pods = self.local_pods.read().await;
        pods.contains_key(ip_address)
    }

    /// Resolves target interface index:
    /// - If target IP is local: returns local pod's TAP interface index (bypassing router)
    /// - If target IP is remote: returns local fleetos-router TAP interface index
    pub async fn resolve_egress_if_index(&self, dst_ip: &Ipv4Addr) -> Option<u32> {
        let pods = self.local_pods.read().await;
        if let Some(pod) = pods.get(dst_ip) {
            // Local fast-path (Direct TAP-to-TAP)
            Some(pod.if_index)
        } else {
            // Remote path (Hand off to local fleetos-router)
            let guard = self.router_tap_if_index.lock().await;
            *guard
        }
    }

    /// Initializes eBPF TC ingress classifiers on the host interface
    pub async fn initialize_ebpf(&self) -> Result<()> {
        info!(
            "Initializing NetworkManager eBPF engine on interface: {}",
            self.interface_name
        );

        let engine = EbpfEngine::load_and_attach(&self.interface_name)
            .context("Failed to attach eBPF classifiers to host network interface")?;

        let mut guard = self.ebpf_engine.lock().await;
        *guard = Some(engine);

        Ok(())
    }

    /// Adds or updates a SPIFFE-to-SPIFFE port authorization rule in the kernel eBPF map
    pub async fn allow_spiffe_traffic(
        &self,
        src_spiffe_id: &str,
        dst_spiffe_id: &str,
        target_port: u16,
    ) -> Result<()> {
        let guard = self.ebpf_engine.lock().await;
        let engine = guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("eBPF engine is not initialized"))?;

        let key = EbpfPolicyKey {
            src_hash: Self::hash_spiffe_id(src_spiffe_id),
            dst_hash: Self::hash_spiffe_id(dst_spiffe_id),
            port: target_port,
            _pad: 0,
        };

        let value = EbpfPolicyValue {
            action: 1, // 1 = ALLOW
            _flags: 0,
            _pad: 0,
        };

        engine.update_policy(key, value).await?;
        info!(
            "Kernel eBPF Policy Allowed: '{}' -> '{}' on port {}",
            src_spiffe_id, dst_spiffe_id, target_port
        );
        Ok(())
    }

    /// Revokes a SPIFFE-to-SPIFFE port authorization rule from the kernel eBPF map
    pub async fn revoke_spiffe_traffic(
        &self,
        src_spiffe_id: &str,
        dst_spiffe_id: &str,
        target_port: u16,
    ) -> Result<()> {
        let guard = self.ebpf_engine.lock().await;
        let engine = guard
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("eBPF engine is not initialized"))?;

        let key = EbpfPolicyKey {
            src_hash: Self::hash_spiffe_id(src_spiffe_id),
            dst_hash: Self::hash_spiffe_id(dst_spiffe_id),
            port: target_port,
            _pad: 0,
        };

        engine.remove_policy(&key).await?;
        info!(
            "Kernel eBPF Policy Revoked: '{}' -> '{}' on port {}",
            src_spiffe_id, dst_spiffe_id, target_port
        );
        Ok(())
    }
}
