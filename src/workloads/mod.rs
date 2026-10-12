// SPDX-License-Identifier: Apache-2.0
//! Workload lifecycle management: reconcile, pod management, probes, runtime adapters.
//!
//! Full-state reconcile is the eviction mechanism: pods absent from the desired
//! frame are terminated with grace periods.

pub mod containerd;
pub mod env;
pub mod image;
pub mod lifecycle;
pub mod microvm;
pub mod netns;
pub mod pod_manager;
pub mod probe_loop;
pub mod probe_manager;
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
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::spiffe::{IdKind, SpiffeId, WorkloadRole};
use fleetos_ebpf_common::HostOrderIpv4;
use std::collections::HashSet;
use std::sync::Mutex as StdMutex;

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
    /// Path to the erofs image cache directory (Phase 7.7.3).
    image_cache_path: std::path::PathBuf,
    /// Source-identity registry (SRC_IDENTITY_MAP), injected (7.2.5).
    src_identity: Option<Arc<dyn SrcIdentityRegistry>>,
    /// Node-local workload IP allocator (7.2.5 / Option B).
    ip_allocator: Arc<StdMutex<NodeIpAllocator>>,
    /// Allocated source IPs per pod (pod_id -> host-order IP), for release on stop.
    pod_source_ips: Arc<StdMutex<HashMap<String, u32>>>,
    // Delegated signing dependencies (optional; set via with_delegation).
    control_client: Option<Arc<crate::client::ControlPlaneClient>>,
    delegated_keys: Option<Arc<std::sync::RwLock<crate::identity::degraded::DelegatedKeyManager>>>,
    node_spiffe_id: Option<SpiffeId>,
    delegated_key_ttl_secs: u64,
    /// Optional event reporter for pod lifecycle events.
    event_reporter: Option<Arc<crate::observability::pod_events::PodEventReporter>>,
    /// Per-pod probe runners (Phase 8.1).
    probes: Option<Arc<RwLock<probe_manager::ProbeManager>>>,
    /// Phase 8.2: attestation registrar (VsockAttestServer behind a trait seam).
    attestation: Option<Arc<dyn crate::vsock_attest::AttestationRegistrar>>,
    /// Phase 8.2: shared eBPF manager for POD_NET_COUNTERS pre-population.
    ebpf_manager: Option<Arc<std::sync::Mutex<crate::ebpf::EbpfManager>>>,
    /// Phase 8.2: boot artifact paths for the host-measured boot measurement.
    kernel_path: std::path::PathBuf,
    guest_init_path: std::path::PathBuf,
}

impl WorkloadManager {
    pub fn new(
        containerd: Arc<ContainerdAdapter>,
        volume_config: VolumeConfig,
        pod_manager: Arc<RwLock<PodManager>>,
        net_guard: Option<Arc<dyn NetGuard>>,
        trust_domain: String,
        src_identity: Option<Arc<dyn SrcIdentityRegistry>>,
        ip_allocator: Arc<StdMutex<NodeIpAllocator>>,
        image_cache_path: std::path::PathBuf,
    ) -> Self {
        Self {
            containerd,
            volume_config,
            pod_manager,
            cid_allocator: Arc::new(RwLock::new(VsockCidAllocator::new(3))),
            net_guard,
            microvms: Arc::new(RwLock::new(HashMap::new())),
            trust_domain,
            image_cache_path,
            src_identity,
            ip_allocator,
            pod_source_ips: Arc::new(StdMutex::new(HashMap::new())),
            control_client: None,
            delegated_keys: None,
            node_spiffe_id: None,
            delegated_key_ttl_secs: crate::identity::degraded::DEFAULT_DELEGATED_KEY_TTL_SECS,
            event_reporter: None,
            probes: None,
            attestation: None,
            ebpf_manager: None,
            kernel_path: std::path::PathBuf::from("/var/lib/fleetos/vmlinux"),
            guest_init_path: std::path::PathBuf::from("/var/lib/fleetos/fleetos-guest-init"),
        }
    }

    pub fn with_event_reporter(
        mut self,
        reporter: Arc<crate::observability::pod_events::PodEventReporter>,
    ) -> Self {
        self.event_reporter = Some(reporter);
        self
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

    /// Attach the delegated-signing dependencies (7.5). Optional; without
    /// these, workload SVIDs are left empty (fail-closed) at config push.
    pub fn with_delegation(
        mut self,
        control_client: Arc<crate::client::ControlPlaneClient>,
        delegated_keys: Arc<std::sync::RwLock<crate::identity::degraded::DelegatedKeyManager>>,
        node_spiffe_id: SpiffeId,
        delegated_key_ttl_secs: u64,
    ) -> Self {
        self.control_client = Some(control_client);
        self.delegated_keys = Some(delegated_keys);
        self.node_spiffe_id = Some(node_spiffe_id);
        self.delegated_key_ttl_secs = delegated_key_ttl_secs;
        self
    }

    /// Phase 8.2: attach the attestation registrar (VsockAttestServer).
    pub fn with_attestation(
        mut self,
        registrar: Arc<dyn crate::vsock_attest::AttestationRegistrar>,
    ) -> Self {
        self.attestation = Some(registrar);
        self
    }

    /// Phase 8.2: attach the shared eBPF manager (for counters pre-population).
    pub fn with_ebpf_manager(
        mut self,
        ebpf_manager: Arc<std::sync::Mutex<crate::ebpf::EbpfManager>>,
    ) -> Self {
        self.ebpf_manager = Some(ebpf_manager);
        self
    }

    /// Phase 8.2: override boot artifact paths (kernel + guest-init) used for
    /// the host-measured boot measurement.
    pub fn with_boot_artifact_paths(
        mut self,
        kernel_path: std::path::PathBuf,
        guest_init_path: std::path::PathBuf,
    ) -> Self {
        self.kernel_path = kernel_path;
        self.guest_init_path = guest_init_path;
        self
    }

    /// Attach the probe manager (Phase 8.1).
    pub fn with_probes(mut self, probe_manager: Arc<RwLock<probe_manager::ProbeManager>>) -> Self {
        self.probes = Some(probe_manager);
        self
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

        let mounts = volumes::prepare_mounts(
            &self.volume_config,
            &pod_id,
            &pod_spec.volumes,
            &pod_spec.volume_mounts,
        )?;

        // 7.6.1: real fingerprint from the workload's SPIFFE identity + role.
        let fp = workload_fingerprint(
            &self.trust_domain,
            &pod_spec.tenant_id,
            &spec.workload_id,
            &spec.role,
        )?;

        // 7.5.1: request a delegated signing key for this workload so its SVID
        // can be generated at config push (and later renewed in degraded mode).
        // Awaited so the key is installed before the guest connects for config
        // push; a failure is non-fatal (config push fails closed with an empty SVID).
        if let (Some(client), Some(keys), Some(node_id)) = (
            &self.control_client,
            &self.delegated_keys,
            &self.node_spiffe_id,
        ) {
            let workload_spiffe_id = SpiffeId::new(
                &self.trust_domain,
                &pod_spec.tenant_id,
                IdKind::Sa,
                &spec.workload_id,
            );
            if let Err(e) = crate::identity::degraded::request_and_install(
                client,
                keys,
                node_id,
                &workload_spiffe_id,
                pod_spec.ordinal,
                self.delegated_key_ttl_secs,
            )
            .await
            {
                tracing::warn!(
                    target = %workload_spiffe_id,
                    error = %e,
                    "delegated key request failed at boot; workload SVID will be empty (fail-closed)"
                );
            }
        }

        // 8.3 (Ruling H) + 8.2.4: BOTH runtimes get an agent-assigned /30 pair.
        // The workload IP is registered in SRC_IDENTITY_MAP and POD_NET_COUNTERS
        // BEFORE boot so the first packet is attributable (fail-closed otherwise).
        let mut registered_ip: Option<HostOrderIpv4> = None;
        let (gw_ip, wl_ip) = {
            let (gw, wl) = self
                .ip_allocator
                .lock()
                .unwrap()
                .allocate_p2p_pair(&pod_id)?;
            if let Some(registry) = &self.src_identity {
                let ho = HostOrderIpv4(wl);
                if let Err(e) = registry.register(ho, &fp) {
                    self.ip_allocator.lock().unwrap().release_p2p_pair(&pod_id);
                    return Err(e);
                }
                registered_ip = Some(ho);
            }
            // 8.2.6/8.3.4: pre-populate POD_NET_COUNTERS for the workload source IP.
            if let Some(ebpf) = &self.ebpf_manager {
                if let Ok(mut mgr) = ebpf.lock() {
                    let _ = crate::ebpf::maps::prepopulate_pod_counters(
                        &mut mgr.pod_net_counters,
                        HostOrderIpv4(wl),
                    );
                }
            }
            (gw, wl)
        };

        let boot_result = match spec.runtime {
            RuntimeKind::Containerd => self.boot_containerd(spec, &mounts, wl_ip, gw_ip).await,
            RuntimeKind::CloudHypervisor => self.boot_microvm(spec, &mounts, wl_ip, gw_ip).await,
        };

        let handle = match boot_result {
            Ok(h) => h,
            Err(e) => {
                // Boot failed: release registered identity + IP pair (no leak).
                // (Containerd destroys its own netns internally on failure.)
                if let (Some(registry), Some(ho)) = (&self.src_identity, registered_ip) {
                    let _ = registry.unregister(ho);
                }
                self.ip_allocator.lock().unwrap().release_p2p_pair(&pod_id);
                return Err(e);
            }
        };

        let mut pod = Pod::new(
            pod_id.clone(),
            spec.workload_id.clone(),
            pod_spec.tenant_id.clone(),
            spec.role.clone(),
            spec.runtime,
            fp,
        );

        pod.state = PodState::Booting;
        pod.pid = Some(handle);
        pod.mark_started();
        if let Some(ho) = registered_ip {
            self.pod_source_ips
                .lock()
                .unwrap()
                .insert(pod_id.clone(), ho.0);
        }
        self.pod_manager.write().await.add_pod(pod);

        // Phase 8.1: register a probe runner for this pod.
        if let Some(probe_mgr) = &self.probes {
            let runner = probes::ProbeSetRunner::new(
                spec.pod_spec.as_ref().and_then(|ps| ps.probes.as_ref()),
            );
            probe_mgr.write().await.register_pod(&pod_id, runner);
        }
        Ok(handle)
    }

    async fn boot_containerd(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
        container_ip: u32,
        gateway_ip: u32,
    ) -> Result<u32, AgentError> {
        let pod_spec = spec
            .pod_spec
            .as_ref()
            .ok_or_else(|| AgentError::Workload("containerd boot requires full PodSpec".into()))?;
        let pod_id = pod_spec
            .pod_id
            .clone()
            .unwrap_or_else(|| spec.workload_id.clone());

        // 8.3.2: create + configure the container's network namespace.
        let ns = netns::create_netns(&pod_id).await?;
        if let Err(e) = netns::configure_netns(&pod_id, container_ip, gateway_ip).await {
            let _ = netns::destroy_netns(&pod_id).await;
            return Err(e);
        }

        match self.containerd.boot(spec, mounts, &ns).await {
            Ok(pid) => Ok(pid),
            Err(e) => {
                let _ = netns::destroy_netns(&pod_id).await;
                Err(e)
            }
        }
    }

    async fn boot_microvm(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
        guest_ip: u32,
        gateway_ip: u32,
    ) -> Result<u32, AgentError> {
        // Fail-closed before side effects: reject mounts this runtime cannot honor.
        microvm::validate_microvm_mounts(mounts)?;

        // Allocate a VSOCK CID for this MicroVM.
        let vsock_cid = self.cid_allocator.write().await.allocate();
        let interface = format!("vmtap{}", vsock_cid);

        let guard = match &self.net_guard {
            Some(guard) => guard,
            None => {
                return Err(AgentError::Workload(
                    "boot aborted: NetGuard (VmNetGuard) not armed before MicroVM boot (fail-closed)"
                        .into(),
                ));
            }
        };

        // BOOT-RACE GUARD (non-negotiable): arm BEFORE the VM boots / TAP comes up.
        guard.arm(&interface)?;

        // 7.8.1 + 8.2.7/8.2.8: wrap the boot so we clean up (disarm NetGuard,
        // unregister attestation) if ANY step fails before the VM runs.
        let result = self
            .boot_microvm_inner(spec, mounts, vsock_cid, &interface, guest_ip, gateway_ip)
            .await;
        match result {
            Ok(handle) => Ok(handle),
            Err(e) => {
                tracing::error!(
                    vsock_cid,
                    error = %e,
                    "MicroVM boot failed; disarming NetGuard + unregistering attestation"
                );
                if let Some(reg) = &self.attestation {
                    reg.unregister_boot_measurement(vsock_cid);
                    reg.unregister_workload_context(vsock_cid);
                }
                let _ = guard.disarm(&interface);
                Err(e)
            }
        }
    }

    async fn boot_microvm_inner(
        &self,
        spec: &WorkloadSpec,
        mounts: &[PreparedMount],
        vsock_cid: u32,
        interface: &str,
        guest_ip: u32,
        gateway_ip: u32,
    ) -> Result<u32, AgentError> {
        // Create + boot the MicroVM adapter.
        let api_socket = format!("/run/fleetos/vm/{}/api.sock", vsock_cid);
        let adapter = Arc::new(MicroVmAdapter::new(&api_socket)?);

        // Phase 7.7.3: Resolve OCI image to erofs rootfs path.
        let rootfs_path =
            crate::workloads::image::oci_to_erofs(&spec.image, &self.image_cache_path)?;
        let rootfs_path_str = rootfs_path.to_string_lossy().to_string();

        // 8.2.2: Compute the boot measurement over kernel + rootfs + guest-init.
        let measurement = crate::vsock_attest::measure::compute_boot_measurement(
            &self.kernel_path,
            &rootfs_path,
            &self.guest_init_path,
        )?;

        // 8.2.3 + 8.2.4: Build the workload context, feeding the allocated
        // guest IP so guest-init gets real networking (resolves TODO 7.7).
        let context = crate::vsock_attest::WorkloadContext {
            pod_spec: spec.pod_spec.clone().unwrap_or_default(),
            guest_ip: guest_ip.to_be_bytes(),
            netmask: [255, 255, 255, 252], // /30 point-to-point
            gateway: gateway_ip.to_be_bytes(),
        };

        // 8.2.2/8.2.3: Register measurement + context BEFORE boot so the guest
        // can attest immediately. Warn (not fail) if no registrar is wired so
        // existing net-guard tests still exercise the boot path.
        if let Some(reg) = &self.attestation {
            reg.register_boot_measurement(vsock_cid, measurement);
            reg.register_workload_context(vsock_cid, context);
        } else {
            tracing::warn!(
                vsock_cid,
                "no attestation registrar configured; MicroVM attestation will fail"
            );
        }

        let gateway_ip_addr = std::net::Ipv4Addr::from(gateway_ip.to_be_bytes());
        let handle = adapter
            .boot(
                spec,
                vsock_cid,
                mounts,
                &rootfs_path_str,
                interface,
                gateway_ip_addr,
            )
            .await?;
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

        // Phase 8.1: transition to Terminating and unregister probes.
        {
            let mut pm = self.pod_manager.write().await;
            if let Some(pod) = pm.get_pod_mut(pod_id) {
                pod.begin_eviction();
            }
        }
        if let Some(probe_mgr) = &self.probes {
            probe_mgr.write().await.unregister_pod(pod_id);
        }

        if let Some(ref event_reporter) = self.event_reporter {
            if let Err(e) = event_reporter
                .record_event(pod_id, "Evicting", "", "")
                .await
            {
                tracing::warn!(pod_id = %pod_id, error = %e, "failed to emit Evicting event");
            }
        }

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
                // 8.2.8: unregister attestation material for this CID.
                if let Some(reg) = &self.attestation {
                    reg.unregister_boot_measurement(handle as u32);
                    reg.unregister_workload_context(handle as u32);
                }
            }
        }

        // 7.2.5 / 8.3: unregister source identity + release the /30 IP pair.
        // Extract the value first so the MutexGuard drops immediately.
        let src_ip_opt = self.pod_source_ips.lock().unwrap().remove(pod_id);
        if let Some(src_ip) = src_ip_opt {
            if let Some(registry) = &self.src_identity {
                if let Err(e) = registry.unregister(HostOrderIpv4(src_ip)) {
                    tracing::warn!(pod_id, error = %e, "SRC_IDENTITY_MAP unregister failed");
                }
            }
            self.ip_allocator.lock().unwrap().release_p2p_pair(pod_id);
            if runtime == RuntimeKind::Containerd {
                let _ = netns::destroy_netns(pod_id).await;
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

/// Compute a workload's canonical identity fingerprint.
///
/// 7.6.1 / Rule #1: uses `IdentityFingerprint::of` ONLY — never
/// `of_with_ordinal` — so every replica of a (tenant, service, role) shares a
/// single fingerprint and role-based load balancing works. Never the zero
/// placeholder.
pub fn workload_fingerprint(
    trust_domain: &str,
    tenant_id: &str,
    workload_id: &str,
    role: &str,
) -> Result<IdentityFingerprint, AgentError> {
    let spiffe = SpiffeId::new(trust_domain, tenant_id, IdKind::Sa, workload_id);
    let role = WorkloadRole::try_from(role)
        .map_err(|e| AgentError::Workload(format!("invalid workload role {role:?}: {e}")))?;
    Ok(IdentityFingerprint::of(&spiffe, Some(&role)))
}

/// Source-identity registry seam (7.2.5 / Option B). Implemented by the eBPF
/// layer (`VmNetGuardAdapter`) and injected so the workloads layer stays
/// eBPF-free — same precedent as `NetGuard`.
pub trait SrcIdentityRegistry: Send + Sync {
    fn register(
        &self,
        source_ip: HostOrderIpv4,
        fingerprint: &IdentityFingerprint,
    ) -> Result<(), AgentError>;
    fn unregister(&self, source_ip: HostOrderIpv4) -> Result<(), AgentError>;
}

/// Node-local workload IP allocator (7.2.5 / Option B).
///
/// Assigns each MicroVM a node-local source IP at boot. The range is
/// node-local and NOT globally routable; control-side per-node subnet
/// assignment is a future mechanism. Rejects ranges inside the 240.0.0.0/4
/// dummy space (reserved for service identities).
pub struct NodeIpAllocator {
    base: u32,
    host_count: u32,
    next_offset: u32,
    free: HashSet<u32>,
    allocated: HashMap<u32, String>, // offset -> pod_id
}

impl NodeIpAllocator {
    pub fn new(cidr: &str) -> Result<Self, AgentError> {
        let (ip, prefix) = parse_cidr(cidr)?;
        if !(8..=28).contains(&prefix) {
            return Err(AgentError::Workload(format!(
                "workload_ip_cidr prefix /{prefix} outside 8..=28"
            )));
        }
        let mask = if prefix == 0 {
            0
        } else {
            !0u32 << (32 - prefix)
        };
        let base = ip & mask;
        // Reject overlap with the 240.0.0.0/4 dummy space.
        if base >> 28 == 0xF {
            return Err(AgentError::Workload(
                "workload_ip_cidr overlaps the 240.0.0.0/4 dummy space".into(),
            ));
        }
        let host_count = 1u32 << (32 - prefix);
        Ok(Self {
            base,
            host_count,
            next_offset: 1,
            free: HashSet::new(),
            allocated: HashMap::new(),
        })
    }

    pub fn allocate(&mut self, pod_id: &str) -> Result<u32, AgentError> {
        let offset = if let Some(o) = self.free.iter().next().copied() {
            self.free.remove(&o);
            o
        } else {
            let o = self.next_offset;
            if o >= self.host_count - 1 {
                return Err(AgentError::Workload(
                    "node workload IP space exhausted".into(),
                ));
            }
            self.next_offset += 1;
            o
        };
        self.allocated.insert(offset, pod_id.to_string());
        Ok(self.base + offset)
    }

    pub fn release(&mut self, pod_id: &str) {
        self.allocated.retain(|offset, pid| {
            if pid == pod_id {
                self.free.insert(*offset);
                false
            } else {
                true
            }
        });
    }

    pub fn allocated_count(&self) -> usize {
        self.allocated.len()
    }

    /// Allocate a /30-aligned point-to-point pair (gateway + guest) for a MicroVM.
    /// Returns `(gateway_ip, guest_ip)` in canonical (big-endian numeric) form.
    ///
    /// Reuses a freed /30-aligned pair when one is available; otherwise advances
    /// `next_offset` to the next /30 boundary. The gateway sits at offset ≡ 1 (mod 4),
    /// the guest at the following offset; the other two offsets of the /30 are reserved.
    pub fn allocate_microvm_pair(&mut self, pod_id: &str) -> Result<(u32, u32), AgentError> {
        // Try to reuse a freed /30-aligned pair: both offsets free, first ≡ 1 (mod 4).
        let mut candidates: Vec<u32> = self.free.iter().copied().collect();
        candidates.sort_unstable();
        let mut reuse: Option<u32> = None;
        for &o in &candidates {
            if o % 4 == 1 && self.free.contains(&(o + 1)) {
                reuse = Some(o);
                break;
            }
        }
        if let Some(o) = reuse {
            self.free.remove(&o);
            self.free.remove(&(o + 1));
            self.allocated.insert(o, format!("{}:gw", pod_id));
            self.allocated.insert(o + 1, pod_id.to_string());
            return Ok((self.base + o, self.base + o + 1));
        }

        // No reusable pair; advance to the next /30 boundary.
        let mut o = self.next_offset;
        while o % 4 != 1 {
            o += 1;
        }
        if o + 1 >= self.host_count - 1 {
            return Err(AgentError::Workload(
                "node workload IP space exhausted".into(),
            ));
        }
        let gw_offset = o;
        let guest_offset = o + 1;
        self.next_offset = o + 4;
        self.allocated.insert(gw_offset, format!("{}:gw", pod_id));
        self.allocated.insert(guest_offset, pod_id.to_string());
        Ok((self.base + gw_offset, self.base + guest_offset))
    }

    /// Release both IPs of a MicroVM /30 pair.
    pub fn release_microvm_pair(&mut self, pod_id: &str) {
        self.allocated.retain(|offset, pid| {
            let belongs = pid == pod_id || *pid == format!("{}:gw", pod_id);
            if belongs {
                self.free.insert(*offset);
            }
            !belongs
        });
    }

    /// Allocate a /30 point-to-point pair (gateway, workload). Generic across
    /// runtimes: MicroVM uses it over a TAP link, containerd over a veth pair.
    pub fn allocate_p2p_pair(&mut self, pod_id: &str) -> Result<(u32, u32), AgentError> {
        self.allocate_microvm_pair(pod_id)
    }

    /// Release a /30 point-to-point pair allocated via `allocate_p2p_pair`.
    pub fn release_p2p_pair(&mut self, pod_id: &str) {
        self.release_microvm_pair(pod_id)
    }
}

fn parse_cidr(cidr: &str) -> Result<(u32, u32), AgentError> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| AgentError::Workload("CIDR missing /prefix".into()))?;
    let ip: std::net::Ipv4Addr = addr
        .parse()
        .map_err(|e| AgentError::Workload(format!("bad CIDR address: {e}")))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|e| AgentError::Workload(format!("bad CIDR prefix: {e}")))?;
    if prefix > 32 {
        return Err(AgentError::Workload("CIDR prefix > 32".into()));
    }
    Ok((u32::from_be_bytes(ip.octets()), prefix))
}
