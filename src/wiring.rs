// SPDX-License-Identifier: Apache-2.0
//! Phase 5 main wiring: watch loop runners connecting the control-plane streams
//! to policy sync, workload reconcile, secret delivery, and route tables.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use futures::{StreamExt, pin_mut};
use tokio::sync::RwLock;

use crate::client::{ControlPlaneClient, unary, watch};
use crate::ebpf::EbpfManager;
use crate::error::AgentError;
use crate::identity::keystore::TpmSealedStore;
use crate::identity::svid::SvidState;
use crate::storage::Storage;
use crate::vsock_attest::config_push::WorkloadConfigBuilder;
use crate::workloads::{WorkloadManager, WorkloadSpec};
use fleetos_core::proto::fleetos::watch_event::Event;
use fleetos_core::proto::fleetos::{RouteEntry, SealedSecret};
use fleetos_core::spiffe::SpiffeId;
use fleetos_core::vsock_proto::DummyIpRouteConfig;

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

/// WatchRoutes → config_builder dummy_ip_routes + containerd /etc/hosts.
pub async fn run_routes_watch(
    control_client: Arc<ControlPlaneClient>,
    config_builder: Arc<WorkloadConfigBuilder>,
    containerd: Arc<crate::workloads::containerd::ContainerdAdapter>,
    _trust_domain: String,
) {
    let stream = watch::watch_routes(control_client);
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(update) => {
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
                tracing::debug!(routes = update.routes.len(), "route table updated");
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
pub async fn run_sag_watch(
    control_client: Arc<ControlPlaneClient>,
    ebpf_manager: Arc<std::sync::Mutex<EbpfManager>>,
) {
    let stream = watch::watch_sag(control_client);
    pin_mut!(stream);
    while let Some(result) = stream.next().await {
        match result {
            Ok(update) => {
                if let Err(e) = sync_policy(&ebpf_manager, &update) {
                    tracing::warn!(error = %e, "policy sync failed");
                } else {
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
/// TODO: Wire to fleetos-policy-compiler once its public API is stabilized.
/// For now, log the update and return Ok (fail-closed: no policy = default deny).
fn sync_policy(
    _ebpf_manager: &Arc<std::sync::Mutex<EbpfManager>>,
    update: &fleetos_core::proto::fleetos::SagUpdate,
) -> Result<(), AgentError> {
    tracing::info!(
        version = update.version,
        rules = update.rules.len(),
        revoked = update.revoked_spiffe_ids.len(),
        "SAG update received (policy compiler wiring pending)"
    );
    // Default-deny is already enforced by eBPF; no action needed until compiler is wired.
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
    secrets: Arc<RwLock<HashMap<String, Vec<u8>>>>,
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
        self.secrets
            .write()
            .await
            .insert(spiffe_id.to_string(), plaintext.clone());
        self.deliver(spiffe_id, &plaintext).await?;
        tracing::info!(spiffe_id, "secret delivered");
        Ok(())
    }

    fn unseal(&self, sealed: &SealedSecret) -> Result<Vec<u8>, AgentError> {
        let node_private_key = self
            .keystore
            .load_sealing_secret(&self.storage)?
            .ok_or_else(|| AgentError::Secret("node sealing private key missing".into()))?;

        // TODO: Wire to fleetos_core::crypto::unseal once the API is finalized.
        // For now, fail-closed: return an error to prevent plaintext leakage.
        let _ = node_private_key;
        let _ = sealed;
        Err(AgentError::Secret(
            "X25519 unseal not yet wired (fail-closed: secret delivery disabled until crypto API is integrated)".into()
        ))
    }

    async fn deliver(&self, spiffe_id: &str, plaintext: &[u8]) -> Result<(), AgentError> {
        let safe_name = spiffe_id.replace(['/', ':'], "_");
        let path = std::path::PathBuf::from(format!("/run/fleetos/secrets/{safe_name}"));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, plaintext)?;
        Ok(())
    }
}
