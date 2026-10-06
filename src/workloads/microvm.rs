// SPDX-License-Identifier: Apache-2.0
//! Cloud Hypervisor MicroVM runtime adapter.
//!
//! Drives Cloud Hypervisor through the `cloud-hypervisor-client` SDK over its
//! Unix API socket (Dark Overlay: no HTTP, no open ports — colocated on node).
//!
//! BOOT-RACE GUARD (non-negotiable): the caller (WorkloadManager) MUST have
//! armed VmNetGuard (TC attach + SRC_IDENTITY_MAP + DUMMY_IP_ROUTE_MAP +
//! BOOT_GATE) BEFORE this adapter brings the TAP up and boots the VM.

use super::WorkloadSpec;
use super::volumes::{PreparedMount, VolumeSource};
use crate::error::AgentError;
use cloud_hypervisor_client::apis::DefaultApi;

/// VSOCK CID allocator. CIDs are unique per node; >= 3 (0/1/2 reserved).
pub struct VsockCidAllocator {
    next_cid: u32,
}

impl VsockCidAllocator {
    pub fn new(start_cid: u32) -> Self {
        Self {
            next_cid: start_cid.max(3),
        }
    }

    pub fn allocate(&mut self) -> u32 {
        let cid = self.next_cid;
        self.next_cid += 1;
        cid
    }
}

/// Cloud Hypervisor adapter. Talks to the CH API over a Unix socket.
pub struct MicroVmAdapter {
    /// Path to the Cloud Hypervisor API socket for this VM.
    api_socket: String,
    /// The cloud-hypervisor-client API client.
    // SDK VERIFICATION POINT: client type + Unix-socket constructor.
    client: cloud_hypervisor_client::SocketBasedApiClient,
}

/// Validate mounts for a MicroVM boot. Fail-closed (CR-CORE-2).
///
/// MicroVMs cannot expose host-backed mounts in v1:
/// - `EmptyDir`: per-pod scratch, provided inside the guest as tmpfs by
///   fleetos-guest-init from `WorkloadConfig.volume_mounts`. Nothing to
///   attach at the Cloud Hypervisor level.
/// - `HostPath`: rejected outright. `prepare_mounts` only emits HostPath when
///   `VolumeConfig.allow_host_path = true`; silently booting without exposing
///   the mount here would leave a declared volume silently missing.
pub fn validate_microvm_mounts(mounts: &[PreparedMount]) -> Result<(), AgentError> {
    for m in mounts {
        match m.source {
            VolumeSource::EmptyDir { .. } => {}
            VolumeSource::HostPath { .. } => {
                return Err(AgentError::Workload(format!(
                    "microvm boot rejected: hostPath volume '{}' cannot be exposed to a MicroVM (CR-CORE-2, fail-closed)",
                    m.name
                )));
            }
        }
    }
    Ok(())
}

impl MicroVmAdapter {
    /// Create the adapter bound to a CH API socket path.
    pub fn new(api_socket: &str) -> Result<Self, AgentError> {
        // SDK VERIFICATION POINT: construct client over Unix socket (not HTTP).
        // The helper handles the hyperlocal connector and Arc<Configuration> wrapping.
        let client = cloud_hypervisor_client::socket_based_api_client(api_socket);
        Ok(Self {
            api_socket: api_socket.to_string(),
            client,
        })
    }

    pub fn api_socket(&self) -> &str {
        &self.api_socket
    }

    /// Boot a MicroVM. Returns the VSOCK CID.
    ///
    /// BOOT-RACE GUARD (non-negotiable): the caller MUST have armed VmNetGuard
    /// (TC attach + map population + BOOT_GATE arm) BEFORE calling this method.
    pub async fn boot(
        &self,
        spec: &WorkloadSpec,
        vsock_cid: u32,
        mounts: &[PreparedMount],
        rootfs_path: &str,
        tap_name: &str,
        gateway_ip: std::net::Ipv4Addr,
    ) -> Result<u32, AgentError> {
        // CR-CORE-2 fail-closed mount gate: reject before touching any SDK state.
        validate_microvm_mounts(mounts)?;

        let pod_spec = spec
            .pod_spec
            .as_ref()
            .ok_or_else(|| AgentError::Workload("microvm boot requires full PodSpec".into()))?;
        let (vcpus, mem_mb) = match pod_spec.resources.as_ref() {
            Some(r) => (r.vcpus as u8, r.memory_mb as u64),
            None => (1, 512),
        };

        use cloud_hypervisor_client::models::{
            CpusConfig, DiskConfig, MemoryConfig, NetConfig, PayloadConfig, VmConfig, VsockConfig,
        };

        let cpus = CpusConfig {
            boot_vcpus: vcpus as i32,
            max_vcpus: vcpus as i32,
            ..Default::default()
        };

        let memory = MemoryConfig {
            size: (mem_mb * 1024 * 1024) as i64,
            ..Default::default()
        };

        // PayloadConfig is NOT an Option on VmConfig
        let payload = PayloadConfig {
            kernel: Some("/var/lib/fleetos/vmlinux".to_string()),
            ..Default::default()
        };

        let disk = DiskConfig {
            path: Some(rootfs_path.to_string()),
            readonly: Some(true),
            ..Default::default()
        };

        // VsockConfig.socket is a String, NOT an Option<String>
        let vsock = VsockConfig {
            cid: vsock_cid as i64,
            socket: format!("/run/fleetos/vms/{}.vsock", spec.workload_id),
            ..Default::default()
        };

        let net = NetConfig {
            tap: Some(tap_name.to_string()),
            ip: Some(gateway_ip.to_string()),
            mask: Some("255.255.255.252".to_string()),
            num_queues: Some(2),
            queue_size: Some(256),
            id: Some(format!("net-{}", spec.workload_id)),
            ..Default::default()
        };

        let vm_config = VmConfig {
            cpus: Some(cpus),
            memory: Some(memory),
            payload, // Direct assignment, no Some()
            disks: Some(vec![disk]),
            vsock: Some(vsock),
            net: Some(vec![net]),
            ..Default::default()
        };

        // Use self.client directly (no connect method exists)
        self.client
            .create_vm(vm_config)
            .await
            .map_err(|e| AgentError::Workload(format!("CH vm.create: {e}")))?;

        self.client
            .boot_vm()
            .await
            .map_err(|e| AgentError::Workload(format!("CH vm.boot: {e}")))?;

        tracing::info!(
            workload_id = %spec.workload_id,
            cid = vsock_cid,
            tap = %tap_name,
            "Cloud Hypervisor MicroVM booted"
        );

        Ok(vsock_cid)
    }

    /// Stop a MicroVM: graceful shutdown → grace wait → force kill.
    pub async fn stop(&self, _vsock_cid: u32, grace_period_secs: u64) -> Result<(), AgentError> {
        // SDK VERIFICATION POINT: shutdown_vm / delete_vm call names.
        let _ = self
            .client
            .shutdown_vm()
            .await
            .map_err(|e| AgentError::Workload(format!("CH vm.shutdown: {e}")))?;
        tokio::time::sleep(std::time::Duration::from_secs(grace_period_secs)).await;
        let _ = self.client.delete_vm().await;
        tracing::info!(socket = %self.api_socket, "cloud-hypervisor MicroVM stopped");
        Ok(())
    }

    /// Vertical scaling: hotplug vCPUs / memory on a running VM.
    /// (Directive: workload scaling is part of Phase 4.)
    pub async fn resize(&self, vcpus: u8, memory_mb: u64) -> Result<(), AgentError> {
        // SDK VERIFICATION POINT: vm_resize_put + ResizePayload shape.
        use cloud_hypervisor_client::models::VmResize;
        let resize = VmResize {
            desired_vcpus: Some(vcpus as i32),
            desired_ram: Some((memory_mb * 1024 * 1024) as i64),
            ..Default::default()
        };
        self.client
            .vm_resize_put(resize) // <-- FIXED METHOD NAME
            .await
            .map_err(|e| AgentError::Workload(format!("CH vm.resize: {e}")))?;
        tracing::info!(vcpus, memory_mb, "cloud-hypervisor MicroVM resized");
        Ok(())
    }
}
