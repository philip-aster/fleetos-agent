// fleetos-agent/src/ebpf_loader.rs

use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::HashMap as AyaHashMap,
    programs::{SchedClassifier, TcAttachType, tc},
};
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

/// Bake compiled eBPF bytecode directly into the agent binary at compile time
static EBPF_BYTECODE: &[u8] =
    include_bytes!("../../fleetos-ebpf/target/bpfel-unknown-none/release/ebpf");

pub struct EbpfEngine {
    ebpf: Arc<Mutex<Ebpf>>,
}

impl EbpfEngine {
    /// Loads embedded eBPF bytecode into host kernel memory and attaches classifiers
    pub fn load_and_attach(iface: &str) -> Result<Self> {
        info!("Loading embedded eBPF bytecode into kernel...");

        // 1. Load directly from in-memory byte slice using aya::Ebpf::load
        let mut ebpf = Ebpf::load(EBPF_BYTECODE)
            .context("Failed to load embedded eBPF ELF binary into kernel")?;

        // 2. Initialize eBPF logger if present
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            tracing::warn!("eBPF logger initialization skipped/failed: {}", e);
        }

        // 3. Attach Traffic Control (TC) ingress filter classifier
        let program: &mut SchedClassifier = ebpf
            .program_mut("tc_ingress_filter")
            .context("Failed to locate 'tc_ingress_filter' program in eBPF bytecode")?
            .try_into()?;

        program.load()?;

        // Ensure TC qdisc is attached to network interface
        let _ = tc::qdisc_add_clsact(iface);

        program.attach(iface, TcAttachType::Ingress)?;
        info!(
            "Successfully attached tc_ingress_filter to interface: {}",
            iface
        );

        Ok(Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
        })
    }

    /// Safely writes an authorization policy rule into the kernel BPF_MAP_HASH table
    pub async fn update_policy(&self, key: EbpfPolicyKey, value: EbpfPolicyValue) -> Result<()> {
        let mut ebpf = self.ebpf.lock().await;
        let mut policy_map: AyaHashMap<_, EbpfPolicyKey, EbpfPolicyValue> =
            AyaHashMap::try_from(ebpf.map_mut("POLICY_MAP").context("POLICY_MAP not found")?)?;

        // Insert rule into kernel memory (0 = BPF_ANY flags)
        policy_map.insert(key, value, 0)?;
        info!(
            "Kernel Policy Map Updated -> Target Port: {}, Action: {}",
            key.port, value.action
        );

        Ok(())
    }
}
