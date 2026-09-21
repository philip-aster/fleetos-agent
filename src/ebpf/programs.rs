// SPDX-License-Identifier: Apache-2.0
//! eBPF program attachment.
//!
//! Node-wide programs (attach once at startup):
//!   - fleetos_connect4  → cgroup sock_addr (Connect4)
//!   - fleetos_sockops   → cgroup sock_ops
//!
//! Per-interface programs (attach per MicroVM TAP device):
//!   - fleetos_tc_egress → TC egress
//!   - fleetos_tc_ingress → TC ingress
//!
//! Boot-race constraint (Rule #7): TC attach + map population + BOOT_GATE
//! arming must ALL complete synchronously before the TAP device comes up.
//! The `VmNetGuard` type enforces this.

use crate::error::AgentError;
use aya::Ebpf;
use aya::programs::tc::TcAttachType;
use aya::programs::{
    CgroupAttachMode, CgroupSockAddr, SchedClassifier, SockOps,
    cgroup_sock_addr::CgroupSockAddrLinkId, sock_ops::SockOpsLinkId, tc::SchedClassifierLinkId,
};
use std::fs::File;

/// Wrapper enum to hold heterogeneous program link IDs.
///
/// Aya 0.14's cgroup and TC programs return link *IDs* from `attach()`,
/// not `Link` trait objects. The IDs are passed to `program.detach(id)`
/// for explicit detachment. For Batch 4, we store the IDs for lifecycle
/// tracking; actual detach is handled by dropping the `Ebpf` object
/// (which unloads all programs) or by explicit detach in Batch 12 shutdown.
pub enum AttachedLink {
    CgroupSockAddr(CgroupSockAddrLinkId),
    SockOps(SockOpsLinkId),
    SchedClassifier(SchedClassifierLinkId),
}

/// Attach the node-wide cgroup programs (connect4 + sockops).
///
/// Called once at agent startup. These programs intercept all connections
/// on the node, not just MicroVM traffic.
///
/// Returns the link IDs for lifecycle management (detach on shutdown).
pub fn attach_cgroup_programs(
    ebpf: &mut Ebpf,
    cgroup_path: &str,
) -> Result<Vec<AttachedLink>, AgentError> {
    let mut links: Vec<AttachedLink> = Vec::new();

    // Aya requires an open file descriptor to the cgroup directory.
    let cgroup_file = File::open(cgroup_path).map_err(AgentError::Io)?;

    // fleetos_connect4: intercepts connect() syscalls for containerd path.
    let connect4: &mut CgroupSockAddr = ebpf
        .program_mut("fleetos_connect4")
        .ok_or_else(|| AgentError::Ebpf("fleetos_connect4 program missing".into()))?
        .try_into()
        .map_err(|e| AgentError::Ebpf(format!("fleetos_connect4 cast: {}", e)))?;
    connect4
        .load()
        .map_err(|e| AgentError::Ebpf(format!("fleetos_connect4 load: {}", e)))?;
    let link_id = connect4
        .attach(&cgroup_file, CgroupAttachMode::Single)
        .map_err(|e| AgentError::Ebpf(format!("fleetos_connect4 attach: {}", e)))?;
    links.push(AttachedLink::CgroupSockAddr(link_id));
    tracing::info!("fleetos_connect4 attached at {}", cgroup_path);

    // fleetos_sockops: tracks established connections for same-node bypass.
    let sockops: &mut SockOps = ebpf
        .program_mut("fleetos_sockops")
        .ok_or_else(|| AgentError::Ebpf("fleetos_sockops program missing".into()))?
        .try_into()
        .map_err(|e| AgentError::Ebpf(format!("fleetos_sockops cast: {}", e)))?;
    sockops
        .load()
        .map_err(|e| AgentError::Ebpf(format!("fleetos_sockops load: {}", e)))?;
    let link_id = sockops
        .attach(&cgroup_file, CgroupAttachMode::Single)
        .map_err(|e| AgentError::Ebpf(format!("fleetos_sockops attach: {}", e)))?;
    links.push(AttachedLink::SockOps(link_id));
    tracing::info!("fleetos_sockops attached at {}", cgroup_path);

    Ok(links)
}

/// Attach TC programs to a specific network interface.
///
/// Called per MicroVM TAP device. Both egress and ingress are attached.
/// This is part of the boot-race sequence: it MUST complete before the
/// TAP device is brought up.
pub fn attach_tc(
    ebpf: &mut Ebpf,
    interface: &str,
    direction: TcAttachType,
) -> Result<AttachedLink, AgentError> {
    let program_name = match direction {
        TcAttachType::Egress => "fleetos_tc_egress",
        TcAttachType::Ingress => "fleetos_tc_ingress",
        _ => {
            return Err(AgentError::Ebpf(format!(
                "unsupported TC attach direction: {:?}",
                direction
            )));
        }
    };

    // In Aya 0.14, TC classifier programs are `SchedClassifier`.
    let tc: &mut SchedClassifier = ebpf
        .program_mut(program_name)
        .ok_or_else(|| AgentError::Ebpf(format!("{} program missing", program_name)))?
        .try_into()
        .map_err(|e| AgentError::Ebpf(format!("{} cast: {}", program_name, e)))?;

    tc.load()
        .map_err(|e| AgentError::Ebpf(format!("{} load: {}", program_name, e)))?;

    let link_id = tc.attach(interface, direction).map_err(|e| {
        AgentError::Ebpf(format!("{} attach to {}: {}", program_name, interface, e))
    })?;

    tracing::info!(
        "{} attached to {} ({:?})",
        program_name,
        interface,
        direction
    );
    Ok(AttachedLink::SchedClassifier(link_id))
}

/// Boot-race guard for MicroVM TAP devices (Rule #7).
///
/// The eBPF TC classifiers (`fleetos_tc_ingress`/`fleetos_tc_egress`) are
/// attached to the TAP device *before* the MicroVM starts. The eBPF
/// `BOOT_GATE` ensures all overlay traffic drops until the host agent
/// populates the maps and arms the gate.
///
/// **Therefore, `VmNetGuard` MUST complete all eBPF setup before the
/// caller brings up the TAP device.**
pub struct VmNetGuard {
    /// The interface this guard is attached to.
    pub interface: String,
    /// TC egress link ID. Kept for the VM's lifetime; detach handled by Ebpf drop.
    _egress_link: AttachedLink,
    /// TC ingress link ID. Kept for the VM's lifetime; detach handled by Ebpf drop.
    _ingress_link: AttachedLink,
}

impl VmNetGuard {
    /// Arm the boot-race guard for a TAP device.
    ///
    /// This attaches both TC egress and ingress programs to the interface
    /// and arms the BOOT_GATE. All operations are synchronous and blocking.
    ///
    /// **The caller MUST NOT bring up the TAP device until this returns.**
    ///
    /// The returned guard keeps the TC programs attached for the VM's
    /// lifetime. Dropping the guard (and eventually the `Ebpf` object)
    /// detaches the programs.
    pub fn arm(
        ebpf: &mut Ebpf,
        interface: &str,
        boot_gate: &mut aya::maps::Array<aya::maps::MapData, u32>,
    ) -> Result<Self, AgentError> {
        tracing::info!(
            interface = interface,
            "arming VmNetGuard — TC attach + BOOT_GATE"
        );

        // 1. Attach TC egress (synchronous, blocking).
        let egress_link = attach_tc(ebpf, interface, TcAttachType::Egress)?;

        // 2. Attach TC ingress (synchronous, blocking).
        let ingress_link = attach_tc(ebpf, interface, TcAttachType::Ingress)?;

        // 3. Arm the BOOT_GATE.
        //    After this, the kernel ingress path will enforce overlay policy.
        //    Before this, all overlay ingress traffic is dropped (fail-closed).
        super::maps::arm_boot_gate(boot_gate)?;

        tracing::info!(
            interface = interface,
            "VmNetGuard armed — safe to bring up TAP device"
        );

        Ok(Self {
            interface: interface.to_string(),
            _egress_link: egress_link,
            _ingress_link: ingress_link,
        })
    }
}

impl Drop for VmNetGuard {
    fn drop(&mut self) {
        tracing::info!(
            interface = self.interface,
            "VmNetGuard dropped — TC programs will detach when Ebpf is dropped"
        );
        // In Aya 0.14, link IDs don't auto-detach on drop. Explicit detach
        // requires holding a reference to the program and calling
        // `program.detach(link_id)`. For Batch 4, we rely on the `Ebpf`
        // object being dropped (which unloads all programs and detaches
        // all links). Batch 12 will wire explicit detach if needed.
    }
}
