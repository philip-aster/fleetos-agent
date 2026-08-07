use crate::ebpf_loader::EbpfEngine;
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::info;

pub struct IdentitySyncWorker {
    ebpf_engine: Arc<EbpfEngine>,
}

impl IdentitySyncWorker {
    pub fn new(ebpf_engine: Arc<EbpfEngine>) -> Self {
        Self { ebpf_engine }
    }

    /// Background task updating kernel rules dynamically
    pub async fn run_sync_loop(&self) {
        info!("Starting FleetOS Identity Policy Sync Worker...");

        loop {
            // Simulated rule: Allow incoming traffic on port 5432 (e.g., PostgreSQL)
            let test_key = EbpfPolicyKey {
                src_hash: [0x01; 16],
                dst_hash: [0x02; 16],
                port: 5432,
                _pad: 0,
            };

            let test_value = EbpfPolicyValue {
                action: 1, // ALLOW
                _flags: 0,
                _pad: 0,
            };

            if let Err(e) = self.ebpf_engine.update_policy(test_key, test_value).await {
                tracing::error!("Failed to synchronize eBPF kernel policy: {}", e);
            }

            sleep(Duration::from_secs(10)).await;
        }
    }
}
