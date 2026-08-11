pub mod ebpf_loader;
pub mod veth_tap;

use anyhow::{Context, Result};
use ebpf_loader::EbpfEngine;
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

pub struct NetworkManager {
    interface_name: String,
    ebpf_engine: Arc<Mutex<Option<EbpfEngine>>>,
}

impl NetworkManager {
    pub fn new(interface_name: impl Into<String>) -> Self {
        Self {
            interface_name: interface_name.into(),
            ebpf_engine: Arc::new(Mutex::new(None)),
        }
    }

    /// Truncates a BLAKE3 hash of a SPIFFE ID string to 16 bytes for eBPF kernel matching
    pub fn hash_spiffe_id(spiffe_id: &str) -> [u8; 16] {
        let hash = blake3::hash(spiffe_id.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash.as_bytes()[..16]);
        bytes
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
