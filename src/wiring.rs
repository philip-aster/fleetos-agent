// SPDX-License-Identifier: Apache-2.0
//! Phase 5 main wiring: watch loop runners connecting the control-plane streams
//! to policy sync, workload reconcile, secret delivery, and route tables.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use futures::{StreamExt, pin_mut};
use tokio::sync::RwLock;

use crate::client::{ControlPlaneClient, unary, watch};
use crate::ebpf::EbpfManager;
use crate::error::AgentError;
use crate::identity::keystore::TpmSealedStore;
use crate::identity::svid::SvidState;
use crate::policy::sync::{
    PolicySyncState, apply_mutations_to_state, compile_and_sync, exact_key_bytes,
    wildcard_key_bytes,
};
use crate::routes::table::{
    RouteSyncState, apply_mutations_to_maps,
    apply_mutations_to_state as apply_mutations_to_state_table, process_route_update,
};
use crate::secret::deliver::deliver_secret;
use crate::storage::Storage;
use crate::vsock_attest::config_push::WorkloadConfigBuilder;
use crate::workloads::pod_manager::PodManager;
use crate::workloads::{WorkloadManager, WorkloadSpec};
use fleetos_core::proto::fleetos::watch_event::Event;
use fleetos_core::proto::fleetos::{RouteEntry, SealedSecret};
use fleetos_core::spiffe::{IdKind, SpiffeId};
use fleetos_core::vsock_proto::DummyIpRouteConfig;
use zeroize::Zeroizing;

/// Phase 7.4.1 / 7.4.3: full re-evaluation of `router_connected`.
///
/// A pod is router-connected iff its workload SPIFFE ID appears as a route
/// destination in the current full-state route set. Because every `RouteUpdate`
/// is full state (Ruling B), re-evaluating against `routes` naturally sets
/// `router_connected = true` for covered pods and flips it back to `false`
/// for pods whose routes were removed.
///
/// v1 matches on SPIFFE ID only (tenant + workload); `RouteEntry` carries no
/// source field, and per-role precision is a deferred refinement.
pub async fn reevaluate_router_connected(
    pod_manager: &RwLock<PodManager>,
    routes: &[RouteEntry],
    trust_domain: &str,
) {
    let dest_spiffes: HashSet<SpiffeId> = routes
        .iter()
        .filter_map(|r| r.destination_svid.parse::<SpiffeId>().ok())
        .collect();
    let mut pm = pod_manager.write().await;
    for pod in pm.all_pods_mut() {
        let pod_spiffe = SpiffeId::new(trust_domain, &pod.tenant_id, IdKind::Sa, &pod.workload_id);
        pod.router_connected = dest_spiffes.contains(&pod_spiffe);
    }
}

/// Phase 7.4.2: mark every pod `policy_enforced` after a successful policy sync.
///
/// v1 semantics: policy is cluster-wide and default-deny, so once eBPF policy
/// is live it is enforced for all pods. Per-pod rule matching is deferred.
pub async fn mark_all_pods_policy_enforced(pod_manager: &RwLock<PodManager>) {
    let mut pm = pod_manager.write().await;
    for pod in pm.all_pods_mut() {
        pod.policy_enforced = true;
    }
}

/// WatchSchedule → WorkloadManager reconcile.
pub async fn run_schedule_watch(
    control_client: Arc<ControlPlaneClient>,
    workload_manager: Arc<WorkloadManager>,
) {
    let stream = watch::watch_schedule(control_client);
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(update) => {
                let specs: Vec<WorkloadSpec> = update
                    .assignments
                    .iter()
                    .filter_map(|a| WorkloadSpec::from_assignment(a).ok())
                    .collect();
                if let Err(e) = workload_manager.reconcile(&specs).await {
                    tracing::warn!(error = %e, "workload reconcile failed");
                }
            }
            Err(e) => tracing::warn!(error = %e, "watch_schedule stream error"),
        }
    }
}

/// WatchRoutes → config_builder dummy_ip_routes + containerd /etc/hosts + eBPF route maps.
/// Phase 7.2: Populates DUMMY_IP_ROUTE_MAP and LOCAL_WORKLOADS eBPF maps.
pub async fn run_routes_watch(
    control_client: Arc<ControlPlaneClient>,
    config_builder: Arc<WorkloadConfigBuilder>,
    containerd: Arc<crate::workloads::containerd::ContainerdAdapter>,
    ebpf_manager: Arc<std::sync::Mutex<EbpfManager>>,
    trust_domain: String,
    node_name: String,
    pod_manager: Arc<RwLock<PodManager>>,
) {
    // Phase 7.2.4: Construct the agent's own node SpiffeId.
    let own_node_spiffe_id = SpiffeId::new(&trust_domain, "system", IdKind::Node, &node_name);

    // Phase 7.2.1: Own a RouteSyncState instance, initialized empty.
    let mut route_state = RouteSyncState::new();

    let stream = watch::watch_routes(control_client);
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(update) => {
                // Phase 7.2.3: Keep existing /etc/hosts injection path.
                let mut dummy_routes = Vec::new();
                let mut hosts_lines = vec!["127.0.0.1 localhost".to_string()];
                for entry in &update.routes {
                    if let Some(cfg) = route_to_dummy_ip_config(entry) {
                        let ip = format!(
                            "{}.{}.{}.{}",
                            cfg.dummy_ip[0], cfg.dummy_ip[1], cfg.dummy_ip[2], cfg.dummy_ip[3]
                        );
                        hosts_lines.push(format!("{} {}.{}", ip, cfg.service, cfg.tenant));
                        dummy_routes.push(cfg);
                    }
                }
                config_builder.set_dummy_ip_routes(dummy_routes);
                containerd.set_hosts_content(hosts_lines.join("\n") + "\n");

                // Phase 7.2.1: Process the route update through routes::table.
                // This takes the proto RouteUpdate directly and handles conversion.
                match process_route_update(&route_state, &update, &own_node_spiffe_id) {
                    Ok(Some(mutations)) => {
                        // Phase 7.2.2: Lock EbpfManager, apply mutations to eBPF maps.
                        {
                            let mut mgr_guard = match ebpf_manager.lock() {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        "EbpfManager lock poisoned during route sync"
                                    );
                                    continue;
                                }
                            };

                            let mgr = &mut *mgr_guard;
                            let dummy_ip_route = &mut mgr.dummy_ip_route;
                            let local_workloads = &mut mgr.local_workloads;

                            if let Err(e) =
                                apply_mutations_to_maps(&mutations, dummy_ip_route, local_workloads)
                            {
                                tracing::warn!(error = %e, "route map apply failed");
                                continue;
                            }
                        }
                        // Phase 7.2.2: Update RouteSyncState after successful map application.
                        apply_mutations_to_state_table(
                            &mut route_state,
                            &mutations,
                            update.version,
                        );
                        // Phase 7.4.1 / 7.4.3: full re-evaluation of router_connected.
                        reevaluate_router_connected(&pod_manager, &update.routes, &trust_domain)
                            .await;
                        tracing::info!(
                            version = update.version,
                            routes = update.routes.len(),
                            "route table applied to eBPF maps"
                        );
                    }
                    Ok(None) => {
                        // Stale update (version <= current), discarded by process_route_update.
                        tracing::debug!(version = update.version, "stale route update discarded");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "route update processing failed");
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "watch_routes stream error"),
        }
    }
}

/// Convert a RouteEntry to a DummyIpRouteConfig for the MicroVM config push.
fn route_to_dummy_ip_config(entry: &RouteEntry) -> Option<DummyIpRouteConfig> {
    let spiffe = SpiffeId::from_str(&entry.destination_svid).ok()?;
    Some(DummyIpRouteConfig {
        dummy_ip: entry.dummy_ip.to_be_bytes(),
        service: spiffe.name.clone(),
        role: entry.destination_role.clone(),
        tenant: spiffe.tenant.clone(),
    })
}

/// WatchSag → policy sync (eBPF map population).
/// Phase 7.1: Owns PolicySyncState, threads data_trust_domain.
pub async fn run_sag_watch(
    control_client: Arc<ControlPlaneClient>,
    ebpf_manager: Arc<std::sync::Mutex<EbpfManager>>,
    data_trust_domain: String,
    pod_manager: Arc<RwLock<PodManager>>,
) {
    // Phase 7.1.2: Own a PolicySyncState instance, initialized empty, version 0.
    let mut sync_state = PolicySyncState::new();

    let stream = watch::watch_sag(control_client);
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(update) => {
                if let Err(e) =
                    sync_policy(&ebpf_manager, &mut sync_state, &update, &data_trust_domain)
                {
                    tracing::warn!(error = %e, "policy sync failed");
                } else {
                    // Phase 7.4.2: policy is live → mark all pods policy_enforced.
                    mark_all_pods_policy_enforced(&pod_manager).await;
                    tracing::debug!(
                        version = update.version,
                        rules = update.rules.len(),
                        "SAG applied"
                    );
                }
            }
            Err(e) => tracing::warn!(error = %e, "watch_sag stream error"),
        }
    }
}

/// Apply a SagUpdate to the eBPF policy maps.
/// Phase 7.1.1: Full implementation replacing the no-op stub.
///
/// Pipeline: compile_and_sync → apply mutations to eBPF maps → update state.
/// Stale frames (version ≤ current) are discarded by compile_and_sync returning None.
fn sync_policy(
    ebpf_manager: &Arc<std::sync::Mutex<EbpfManager>>,
    sync_state: &mut PolicySyncState,
    update: &fleetos_core::proto::state::SagUpdate,
    data_trust_domain: &str,
) -> Result<(), AgentError> {
    // Phase 7.1.1: Call compile_and_sync with current state, proto rules, version, trust domain.
    // Returns None if the update is stale (version ≤ current).
    let result = compile_and_sync(sync_state, &update.rules, update.version, data_trust_domain)?;

    let Some((mutations, _compiled)) = result else {
        // Stale frame — compile_and_sync already logged it. Nothing to apply.
        return Ok(());
    };

    // Phase 7.1.4: Lock the manager, apply mutations to eBPF maps, release lock.
    {
        let mut mgr = ebpf_manager
            .lock()
            .map_err(|e| AgentError::Ebpf(format!("EbpfManager lock poisoned: {}", e)))?;

        // Apply exact insertions.
        for (key, value) in &mutations.insert_exact {
            let key_bytes = exact_key_bytes(key);
            let value_bytes: [u8; 16] = unsafe { std::mem::transmute(*value) };
            mgr.policy_exact
                .insert(&key_bytes, &value_bytes, 0)
                .map_err(|e| AgentError::Ebpf(format!("POLICY_EXACT insert failed: {}", e)))?;
        }

        // Apply exact deletions.
        for key_bytes in &mutations.delete_exact {
            mgr.policy_exact
                .remove(key_bytes)
                .map_err(|e| AgentError::Ebpf(format!("POLICY_EXACT remove failed: {}", e)))?;
        }

        // Apply wildcard insertions.
        for (key, value) in &mutations.insert_wildcard {
            let key_bytes = wildcard_key_bytes(key);
            let value_bytes: [u8; 16] = unsafe { std::mem::transmute(*value) };
            mgr.policy_wildcard
                .insert(&key_bytes, &value_bytes, 0)
                .map_err(|e| AgentError::Ebpf(format!("POLICY_WILDCARD insert failed: {}", e)))?;
        }

        // Apply wildcard deletions.
        for key_bytes in &mutations.delete_wildcard {
            mgr.policy_wildcard
                .remove(key_bytes)
                .map_err(|e| AgentError::Ebpf(format!("POLICY_WILDCARD remove failed: {}", e)))?;
        }
    } // Lock released here.

    // Phase 7.1.1: Update PolicySyncState after successful map application.
    apply_mutations_to_state(sync_state, &mutations, update.version);

    tracing::info!(
        version = update.version,
        inserted_exact = mutations.insert_exact.len(),
        deleted_exact = mutations.delete_exact.len(),
        inserted_wildcard = mutations.insert_wildcard.len(),
        deleted_wildcard = mutations.delete_wildcard.len(),
        "SAG update applied to eBPF policy maps"
    );

    Ok(())
}

/// WatchEvents → full secret delivery path (fetch → unseal → deliver).
pub async fn run_events_watch(
    control_client: Arc<ControlPlaneClient>,
    handler: Arc<SecretsHandler>,
) {
    let stream = watch::watch_events(control_client);
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(event) => match event.event {
                Some(Event::SecretRotation(n)) => {
                    let version = handler.current_svid_version().await;
                    if let Err(e) = handler.handle_rotation(&n.spiffe_id, version).await {
                        tracing::warn!(spiffe_id = %n.spiffe_id, error = %e, "secret rotation failed");
                    }
                }
                Some(Event::SvidRotation(n)) => {
                    if let Err(e) = handler.handle_rotation(&n.spiffe_id, n.svid_version).await {
                        tracing::warn!(spiffe_id = %n.spiffe_id, error = %e, "svid rotation refetch failed");
                    }
                }
                None => {}
            },
            Err(e) => tracing::warn!(error = %e, "watch_events stream error"),
        }
    }
}

/// Full secret delivery: fetch sealed secret → unseal with node X25519 key → deliver.
pub struct SecretsHandler {
    control_client: Arc<ControlPlaneClient>,
    storage: Arc<Storage>,
    keystore: Arc<TpmSealedStore>,
    svid_state: Arc<RwLock<SvidState>>,
    // Plaintext held in Zeroizing so it's scrubbed on drop (Ruling G hygiene).
    secrets: Arc<RwLock<HashMap<String, Zeroizing<Vec<u8>>>>>,
}

impl SecretsHandler {
    pub fn new(
        control_client: Arc<ControlPlaneClient>,
        storage: Arc<Storage>,
        keystore: Arc<TpmSealedStore>,
        svid_state: Arc<RwLock<SvidState>>,
    ) -> Self {
        Self {
            control_client,
            storage,
            keystore,
            svid_state,
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn current_svid_version(&self) -> u64 {
        self.svid_state.read().await.svid_version
    }

    /// Fetch, unseal, store, and deliver a secret for a workload SPIFFE ID.
    pub async fn handle_rotation(
        &self,
        spiffe_id: &str,
        svid_version: u64,
    ) -> Result<(), AgentError> {
        let sealed = unary::fetch_secret(&self.control_client, spiffe_id, svid_version).await?;
        let plaintext = self.unseal(&sealed)?;
        // Deliver to disk first; only cache in memory once the write succeeds.
        self.deliver(spiffe_id, &plaintext).await?;
        self.secrets
            .write()
            .await
            .insert(spiffe_id.to_string(), plaintext);
        tracing::info!(spiffe_id, "secret delivered");
        Ok(())
    }

    // 7.3.1 / 7.3.2: load the node X25519 sealing key, then delegate to the
    // tested replay-check → proto→core → unseal pipeline in secret::deliver.
    fn unseal(&self, sealed: &SealedSecret) -> Result<Zeroizing<Vec<u8>>, AgentError> {
        let node_private_key = self
            .keystore
            .load_sealing_secret(&self.storage)?
            .ok_or_else(|| AgentError::Secret("node sealing private key missing".into()))?;
        let key_bytes: [u8; 32] = node_private_key.as_slice().try_into().map_err(|_| {
            AgentError::Secret(format!(
                "node sealing key must be 32 bytes (X25519), got {}",
                node_private_key.len()
            ))
        })?;
        deliver_secret(&self.storage, sealed, &key_bytes)
    }

    // 7.3.3: hardened delivery.
    async fn deliver(&self, spiffe_id: &str, plaintext: &[u8]) -> Result<(), AgentError> {
        // Defense-in-depth: reject anything that isn't a well-formed SPIFFE ID
        // before it touches the filesystem.
        let _: SpiffeId = spiffe_id
            .parse()
            .map_err(|e| AgentError::Secret(format!("invalid SPIFFE ID for delivery: {}", e)))?;
        // Sanitization is safe: every path separator ('/', ':') is replaced,
        // so no traversal is possible after substitution.
        let safe_name = spiffe_id.replace(['/', ':'], "_");
        let path = std::path::PathBuf::from(format!("/run/fleetos/secrets/{safe_name}"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, plaintext)?;
        Ok(())
    }
}
