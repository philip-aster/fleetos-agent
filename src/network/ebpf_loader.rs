use anyhow::{Context, Result};
use aya::{
    Ebpf,
    maps::HashMap as AyaHashMap,
    programs::{SchedClassifier, TcAttachType, tc},
};
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

static EBPF_BYTECODE: &[u8] =
    include_bytes!("../../../fleetos-ebpf/target/bpfel-unknown-none/release/ebpf");

pub struct EbpfEngine {
    ebpf: Arc<Mutex<Ebpf>>,
}

impl EbpfEngine {
    pub fn load_and_attach(iface: &str) -> Result<Self> {
        info!(
            "Loading embedded eBPF bytecode into kernel on interface {}...",
            iface
        );

        let mut ebpf = Ebpf::load(EBPF_BYTECODE)
            .context("Failed to load embedded eBPF ELF binary into kernel")?;

        {
            let program: &mut SchedClassifier = ebpf
                .program_mut("tc_ingress_filter")
                .context("Failed to locate 'tc_ingress_filter' program in eBPF bytecode")?
                .try_into()?;

            program.load()?;
        }

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            warn!("eBPF logger initialization skipped/failed: {}", e);
        }

        let _ = tc::qdisc_add_clsact(iface);

        let program: &mut SchedClassifier = ebpf
            .program_mut("tc_ingress_filter")
            .context("Failed to locate 'tc_ingress_filter' for attach")?
            .try_into()?;

        program.attach(iface, TcAttachType::Ingress)?;
        info!(
            "Successfully attached tc_ingress_filter to interface: {}",
            iface
        );

        Ok(Self {
            ebpf: Arc::new(Mutex::new(ebpf)),
        })
    }

    pub async fn update_policy(&self, key: EbpfPolicyKey, value: EbpfPolicyValue) -> Result<()> {
        let mut ebpf = self.ebpf.lock().await;
        let mut policy_map: AyaHashMap<_, EbpfPolicyKey, EbpfPolicyValue> = AyaHashMap::try_from(
            ebpf.map_mut("POLICY_MAP")
                .context("POLICY_MAP not found in eBPF binary")?,
        )?;

        policy_map.insert(key, value, 0)?;
        info!(
            "Kernel eBPF Policy Map Updated -> Port: {}, Action: {}",
            key.port, value.action
        );

        Ok(())
    }

    pub async fn remove_policy(&self, key: &EbpfPolicyKey) -> Result<()> {
        let mut ebpf = self.ebpf.lock().await;
        let mut policy_map: AyaHashMap<_, EbpfPolicyKey, EbpfPolicyValue> = AyaHashMap::try_from(
            ebpf.map_mut("POLICY_MAP")
                .context("POLICY_MAP not found in eBPF binary")?,
        )?;

        // Attempt direct atomic removal from kernel map
        if policy_map.remove(key).is_ok() {
            info!("Kernel eBPF Policy Map Entry Removed -> Port: {}", key.port);
        }

        Ok(())
    }

    /// Maps a local IPv4 address (converted to Network Byte Order) to its target TAP interface index
    pub async fn register_local_redirect(&self, ip: Ipv4Addr, if_index: u32) -> Result<()> {
        let mut ebpf = self.ebpf.lock().await;
        let mut local_map: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(
            ebpf.map_mut("LOCAL_POD_MAP")
                .context("LOCAL_POD_MAP not found in eBPF binary")?,
        )?;

        // Ensure key matches network byte order as evaluated by BPF kernel packet parsing
        let ip_be = u32::from(ip).to_be();
        local_map.insert(ip_be, if_index, 0)?;

        info!(
            "Kernel eBPF Local Redirect Map Registered -> IP: {} (be: {:#x}) -> ifindex: {}",
            ip, ip_be, if_index
        );

        Ok(())
    }

    /// Removes a local IPv4 fast-path entry when a pod is terminated
    pub async fn remove_local_redirect(&self, ip: &Ipv4Addr) -> Result<()> {
        let mut ebpf = self.ebpf.lock().await;
        let mut local_map: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(
            ebpf.map_mut("LOCAL_POD_MAP")
                .context("LOCAL_POD_MAP not found in eBPF binary")?,
        )?;

        let ip_be = u32::from(*ip).to_be();
        if local_map.remove(&ip_be).is_ok() {
            info!("Kernel eBPF Local Redirect Map Removed -> IP: {}", ip);
        }

        Ok(())
    }
}
