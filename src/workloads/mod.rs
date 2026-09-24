// SPDX-License-Identifier: Apache-2.0
//! Workload lifecycle management: reconcile, pod management, probes, runtime adapters.
//!
//! Full-state reconcile is the eviction mechanism: pods absent from the desired
//! frame are terminated with grace periods.

pub mod containerd;
pub mod env;
pub mod lifecycle;
pub mod microvm;
pub mod pod_manager;
pub mod probes;
pub mod reconciler;
pub mod status;
pub mod volumes;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::error::AgentError;
use fleetos_core::proto::state::WorkloadAssignment;
use fleetos_core::proto::workload::PodSpec;

use self::containerd::ContainerdAdapter;
use self::microvm::{MicroVmAdapter, VsockCidAllocator};
use self::pod_manager::{Pod, PodManager, PodState};
use self::reconciler::Reconciler;
use self::volumes::{PreparedMount, VolumeConfig};

/// Runtime kind for a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKind {
    Containerd,
    CloudHypervisor,
}

impl TryFrom<i32> for RuntimeKind {
    type Error = AgentError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RuntimeKind::Containerd),
            1 => Ok(RuntimeKind::CloudHypervisor),
            _ => Err(AgentError::Workload(format!("unknown runtime: {value}"))),
        }
    }
}

impl TryFrom<&str> for RuntimeKind {
    type Error = AgentError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "containerd" => Ok(RuntimeKind::Containerd),
            "cloud-hypervisor" | "cloud_hypervisor" => Ok(RuntimeKind::CloudHypervisor),
            _ => Err(AgentError::Workload(format!("unknown runtime: {value}"))),
        }
    }
}

/// A workload assignment enriched with the full PodSpec.
#[derive(Debug, Clone)]
pub struct WorkloadSpec {
    pub workload_id: String,
    pub runtime: RuntimeKind,
    pub image: String,
    pub role: String,
    pub pod_spec: Option<PodSpec>,
    pub hostname: String,
}

impl WorkloadSpec {
    pub fn from_assignment(assignment: &WorkloadAssignment) -> Result<Self, AgentError> {
        let runtime = RuntimeKind::try_from(assignment.runtime.as_str())?;
        Ok(Self {
            workload_id: assignment.workload_id.clone(),
            runtime,
            image: assignment.image.clone(),
            role: assignment.role.clone(),
            pod_spec: assignment.pod_spec.clone(),
            hostname: assignment.hostname.clone(),
        })
    }

    pub fn runtime(&self) -> RuntimeKind {
        self.runtime
    }
    pub fn image(&self) -> &str {
        &self.image
    }
    pub fn role(&self) -> &str {
        &self.role
    }
}

/// Boot-race guard abstraction. Implemented by the eBPF layer (VmNetGuard) and
/// injected so the workloads layer does not import eBPF internals directly.
///
/// CONTRACT: `arm` MUST be called (and succeed) BEFORE the TAP interface comes
/// up / the VM boots. Fail-closed: if arm fails, the boot is aborted.
pub trait NetGuard: Send + Sync {
    /// Arm the guard for a network interface. Returns Ok only when TC attach +
    /// SRC_IDENTITY_MAP + DUMMY_IP_ROUTE_MAP population + BOOT_GATE are complete.
    fn arm(&self, interface: &str) -> Result<(), AgentError>;
    /// Disarm (teardown) the guard after the workload stops.
    fn disarm(&self, interface: &str) -> Result<(), AgentError>;
}

/// Orchestrates workload lifecycle across runtime adapters.
///
/// Reconciles desired state (from WatchSchedule) against running pods, dispatches
/// boot/stop to the correct adapter, and enforces the boot-race guard ordering
/// for MicroVMs.
pub struct WorkloadManager {
    containerd: Arc<ContainerdAdapter>,
    volume_config: VolumeConfig,
    pod_manager: Arc<RwLock<PodManager>>,
    cid_allocator: Arc<RwLock<VsockCidAllocator>>,
    /// NetGuard impl (VmNetGuard). Injected at wiring time (Phase 5).
    net_guard: Option<Arc<dyn NetGuard>>,
    /// Live MicroVM adapters keyed by vsock_cid.
    microvms: Arc<RwLock<HashMap<u32, Arc<MicroVmAdapter>>>>,
    trust_domain: String,
}

impl WorkloadManager {
    pub fn new(
        containerd: Arc<ContainerdAdapter>,
        volume_config: VolumeConfig,
        pod_manager: Arc<RwLock<PodManager>>,
        net_guard: Option<Arc<dyn NetGuard>>,
        trust_domain: String,
    ) -> Self {
        Self {
            containerd,
            volume_config,
            pod_manager,
            cid_allocator: Arc::new(RwLock::new(VsockCidAllocator::new(3))),
            net_guard,
            microvms: Arc::new(RwLock::new(HashMap::new())),
            trust_domain,
        }
    }

    /// Reconcile desired state against running pods and apply.
    pub async fn reconcile(&self, desired: &[WorkloadSpec]) -> Result<(), AgentError> {
        let result = {
            let pm = self.pod_manager.read().await;
            Reconciler::reconcile(desired, &pm, &self.trust_domain)
        };

        // Evict pods no longer desired (graceful).
        for pod_id in &result.to_evict {
            if let Err(e) = self.evict_pod(pod_id).await {
                tracing::warn!(pod_id, error = %e, "eviction failed");
            }
        }

        // Boot newly desired pods.
        for spec in &result.to_boot {
            if let Err(e) = self.boot_pod(spec).await {
                tracing::warn!(workload = %spec.workload_id, error = %e, "boot failed");
            }
        }

        Ok(())
    }

    /// Boot a single pod on the correct runtime adapter.
    async fn boot_pod(&self, spec: &WorkloadSpec) -> Result<u32, AgentError> {
        let pod_spec = spec
            .pod_spec
            .as_ref()
            .ok_or_else(|| AgentError::Workload("boot requires full PodSpec".into()))?;

        let pod_id = pod_spec
            .pod_id
            .clone()
            .unwrap_or_else(|| spec.workload_id.clone());

        // Prepare volumes (EmptyDir per-pod; HostPath gated).
        let mounts = volumes::prepare_mounts(
            &self.volume_config,
            &pod_id,
            &pod_spec.volumes,
            &pod_spec.volume_mounts,
        )?;

        let handle = match spec.runtime {
            RuntimeKind::Containerd => self.boot_containerd(spec, &mounts).await?,
            RuntimeKind::CloudHypervisor => self.boot_microvm(spec, &mounts).await?,
        };

        // Record the pod in the pod manager.
        // (Fingerprint here is a placeholder; real fingerprint is set when the
        //  workload's SPIFFE ID is known. Wiring refined in Phase 5.)
        let fp = fleetos_core::hash::IdentityFingerprint([0; 16]);
        let mut pod = Pod::new(
            pod_id,
            spec.workload_id.clone(),
            pod_spec.tenant_id.clone(),
            spec.role.clone(),
            spec.runtime,
            fp,
        );
        pod.state = PodState::Booting;
        pod.pid = Some(handle);
        self.pod_manager.write().await.add_pod(pod);

        Ok(handle)
    }

    async fn boot_containerd(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
    ) -> Result<u32, AgentError> {
        self.containerd.boot(spec, mounts).await
    }

    async fn boot_microvm(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
    ) -> Result<u32, AgentError> {
        // Allocate a VSOCK CID for this MicroVM.
        let vsock_cid = self.cid_allocator.write().await.allocate();

        // BOOT-RACE GUARD (non-negotiable): arm BEFORE the VM boots / TAP comes up.
        // Fail-closed: if there is no guard or arming fails, abort the boot.
        let interface = format!("vmtap{}", vsock_cid);
        match &self.net_guard {
            Some(guard) => guard.arm(&interface)?,
            None => {
                return Err(AgentError::Workload(
                    "boot aborted: NetGuard (VmNetGuard) not armed before MicroVM boot (fail-closed)".into(),
                ));
            }
        }

        // Create + boot the MicroVM adapter.
        let api_socket = format!("/run/fleetos/vm/{}/api.sock", vsock_cid);
        let adapter = Arc::new(MicroVmAdapter::new(&api_socket)?);
        let rootfs_path = format!("/var/lib/fleetos/images/{}.erofs", spec.image);
        let handle = adapter.boot(spec, vsock_cid, mounts, &rootfs_path).await?;

        self.microvms.write().await.insert(vsock_cid, adapter);
        Ok(handle)
    }

    /// Evict a pod: stop via the right adapter, tear down scratch, remove record.
    async fn evict_pod(&self, pod_id: &str) -> Result<(), AgentError> {
        let (runtime, handle, grace) = {
            let pm = self.pod_manager.read().await;
            let pod = pm
                .get_pod(pod_id)
                .ok_or_else(|| AgentError::Workload(format!("pod {pod_id} not found")))?;
            let grace = 30; // Default grace; refine from TerminationSpec in Phase 5.
            (pod.runtime, pod.pid.unwrap_or(0), grace)
        };

        match runtime {
            RuntimeKind::Containerd => {
                self.containerd.stop(pod_id, grace).await?;
            }
            RuntimeKind::CloudHypervisor => {
                if let Some(adapter) = self.microvms.write().await.remove(&(handle as u32)) {
                    adapter.stop(handle as u32, grace).await?;
                    let interface = format!("vmtap{}", handle);
                    if let Some(guard) = &self.net_guard {
                        let _ = guard.disarm(&interface);
                    }
                }
            }
        }

        // Tear down per-pod EmptyDir scratch.
        volumes::teardown_pod_scratch(&self.volume_config, pod_id)?;

        self.pod_manager.write().await.remove_pod(pod_id);
        Ok(())
    }

    /// Vertical scaling for a running MicroVM (Phase 4 directive).
    pub async fn resize_microvm(
        &self,
        vsock_cid: u32,
        vcpus: u8,
        memory_mb: u64,
    ) -> Result<(), AgentError> {
        let adapter = self
            .microvms
            .read()
            .await
            .get(&vsock_cid)
            .cloned()
            .ok_or_else(|| AgentError::Workload(format!("no MicroVM for cid {vsock_cid}")))?;
        adapter.resize(vcpus, memory_mb).await
    }
}
