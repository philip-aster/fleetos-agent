// SPDX-License-Identifier: Apache-2.0
//! WorkloadConfig construction and push.
//!
//! After attestation passes, the agent constructs a `WorkloadConfig` and
//! pushes it to the guest over the VSOCK stream. The config contains:
//!   - SVID cert chain + private key (agent-generated keypair, signed by the
//!     delegated key)
//!   - Environment variables
//!   - Volume mounts
//!   - Dummy-IP routes (from routes/table.rs)
//!   - Workload binary path, args
//!   - Trust domain, tenant, service, role
//!   - Guest networking (IP, netmask, gateway)
use super::WorkloadContext;
use super::verify::VerifiedGuest;
use crate::error::AgentError;
use crate::identity::degraded::{DelegatedKeyManager, now_unix};
use fleetos_core::spiffe::{IdKind, SpiffeId};
use fleetos_core::vsock_proto::{DummyIpRouteConfig, VolumeMountConfig, WorkloadConfig};
use std::sync::{Arc, RwLock};

/// Builder for `WorkloadConfig`.
///
/// Holds the agent state needed to construct configs, including the map-based
/// delegated-key manager used to sign workload SVIDs.
pub struct WorkloadConfigBuilder {
    trust_domain: String,
    dummy_ip_routes: RwLock<Vec<DummyIpRouteConfig>>,
    /// Delegated signing keys, one per target workload SPIFFE ID (7.5.4).
    delegated_keys: Arc<RwLock<DelegatedKeyManager>>,
    /// Requested workload SVID validity in seconds. `sign_svid_delegated`
    /// caps this at the delegated key's remaining lifetime.
    svid_ttl_secs: u64,
}

impl WorkloadConfigBuilder {
    pub fn new(
        trust_domain: String,
        delegated_keys: Arc<RwLock<DelegatedKeyManager>>,
        svid_ttl_secs: u64,
    ) -> Self {
        Self {
            trust_domain,
            dummy_ip_routes: RwLock::new(Vec::new()),
            delegated_keys,
            svid_ttl_secs,
        }
    }

    /// Set the dummy-IP routes (driven by WatchRoutes). Takes &self for Arc use.
    pub fn set_dummy_ip_routes(&self, routes: Vec<DummyIpRouteConfig>) {
        *self.dummy_ip_routes.write().unwrap() = routes;
    }

    /// Build a `WorkloadConfig` for a verified guest using the workload context.
    ///
    /// Generates a fresh keypair for the workload, builds a CSR carrying only
    /// the workload SPIFFE ID, and signs it with the delegated key for that
    /// workload (fail-closed: empty SVID fields if no valid key is held).
    pub fn build(
        &self,
        _guest: &VerifiedGuest,
        ctx: &WorkloadContext,
    ) -> Result<WorkloadConfig, AgentError> {
        // Build the workload SPIFFE ID: spiffe://<td>/ns/<tenant>/sa/<workload>.
        // Role/ordinal are NOT part of the URI; sign_svid_delegated stamps them
        // from the delegated key's scope, never from the CSR.
        let workload_spiffe_id = SpiffeId::new(
            &self.trust_domain,
            &ctx.pod_spec.tenant_id,
            IdKind::Sa,
            &ctx.pod_spec.workload_id,
        );

        let now = now_unix();
        let has_key = {
            let mgr = self.delegated_keys.read().unwrap();
            mgr.has_valid_key(&workload_spiffe_id, now)
        };

        // Generate the workload SVID only if a valid delegated key is held
        // (fail-closed: avoid wasted keygen and leave fields empty otherwise).
        let (svid_cert_chain_der, svid_private_key_der) = if has_key {
            // Fresh keypair for the workload.
            let workload_keypair = rcgen::KeyPair::generate()
                .map_err(|e| AgentError::Identity(format!("workload keygen failed: {}", e)))?;
            let private_key_der = workload_keypair.serialize_der();

            // CSR carries ONLY the workload SPIFFE ID (role/ordinal stamped by
            // the delegated signer from the key's scope, never from the CSR).
            let csr = fleetos_core::spiffe::ca::build_csr(&workload_spiffe_id, &workload_keypair)
                .map_err(|e| {
                AgentError::Identity(format!("workload CSR build failed: {}", e))
            })?;

            let validity = std::time::Duration::from_secs(self.svid_ttl_secs);
            let mgr = self.delegated_keys.read().unwrap();
            match mgr.renew_svid_locally(&workload_spiffe_id, &csr.der, validity, now) {
                Ok(cert_der) => {
                    tracing::info!(
                        target = %workload_spiffe_id,
                        "workload SVID signed via delegated key"
                    );
                    (vec![cert_der], private_key_der)
                }
                Err(e) => {
                    tracing::error!(
                        target = %workload_spiffe_id,
                        error = %e,
                        "delegated signing failed; SVID left empty (fail-closed)"
                    );
                    (Vec::new(), Vec::new())
                }
            }
        } else {
            tracing::error!(
                target = %workload_spiffe_id,
                "no valid delegated key; SVID left empty (fail-closed)"
            );
            (Vec::new(), Vec::new())
        };

        // Populate env vars from PodSpec
        let env_vars = ctx
            .pod_spec
            .env
            .iter()
            .map(|e| (e.name.clone(), e.value.clone()))
            .collect();

        // Populate volume mounts from PodSpec
        let volume_mounts = ctx
            .pod_spec
            .volume_mounts
            .iter()
            .map(|vm| VolumeMountConfig {
                name: vm.name.clone(),
                mount_path: vm.mount_path.clone(),
                read_only: vm.read_only,
            })
            .collect();

        // Workload binary path and args are not directly in PodSpec.
        // For now, derive from workload_id or use defaults.
        let workload_binary_path = format!("/usr/bin/{}", ctx.pod_spec.workload_id);
        let workload_args = Vec::new();

        Ok(WorkloadConfig {
            svid_cert_chain_der,
            svid_private_key_der,
            env_vars,
            volume_mounts,
            dummy_ip_routes: self.dummy_ip_routes.read().unwrap().clone(),
            workload_binary_path,
            workload_args,
            trust_domain: self.trust_domain.clone(),
            tenant_id: ctx.pod_spec.tenant_id.clone(),
            service_name: ctx.pod_spec.workload_id.clone(),
            role: ctx.pod_spec.role.clone(),
            guest_ip: ctx.guest_ip,
            netmask: ctx.netmask,
            gateway: ctx.gateway,
        })
    }

    /// Fallback build when no workload context is available (e.g., test/dev).
    pub fn build_fallback(&self, _guest: &VerifiedGuest) -> Result<WorkloadConfig, AgentError> {
        Ok(WorkloadConfig {
            svid_cert_chain_der: Vec::new(),
            svid_private_key_der: Vec::new(),
            env_vars: Vec::new(),
            volume_mounts: Vec::new(),
            dummy_ip_routes: self.dummy_ip_routes.read().unwrap().clone(),
            workload_binary_path: String::new(),
            workload_args: Vec::new(),
            trust_domain: self.trust_domain.clone(),
            tenant_id: String::new(),
            service_name: String::new(),
            role: String::new(),
            guest_ip: [0, 0, 0, 0],
            netmask: [0, 0, 0, 0],
            gateway: [0, 0, 0, 0],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleetos_core::proto::fleetos::{EnvVar, VolumeMount};

    #[test]
    fn config_push_populates_fields_from_context() {
        let builder = WorkloadConfigBuilder::new(
            "fleet.example.internal".to_string(),
            Arc::new(RwLock::new(DelegatedKeyManager::new())),
            3600,
        );
        builder.set_dummy_ip_routes(vec![DummyIpRouteConfig {
            dummy_ip: [240, 0, 0, 45],
            service: "db".to_string(),
            role: "replica".to_string(),
            tenant: "acme".to_string(),
        }]);

        let guest = VerifiedGuest {
            guest_x25519_pubkey: [0x11; 32],
        };

        let ctx = WorkloadContext {
            pod_spec: fleetos_core::proto::fleetos::PodSpec {
                tenant_id: "acme".to_string(),
                workload_id: "db".to_string(),
                role: "primary".to_string(),
                env: vec![EnvVar {
                    name: "FOO".to_string(),
                    value: "bar".to_string(),
                }],
                volume_mounts: vec![VolumeMount {
                    name: "scratch".to_string(),
                    mount_path: "/scratch".to_string(),
                    read_only: false,
                }],
                ..Default::default()
            },
            guest_ip: [10, 0, 0, 2],
            netmask: [255, 255, 255, 0],
            gateway: [10, 0, 0, 1],
        };

        let config = builder.build(&guest, &ctx).unwrap();
        assert_eq!(config.trust_domain, "fleet.example.internal");
        assert_eq!(config.tenant_id, "acme");
        assert_eq!(config.service_name, "db");
        assert_eq!(config.role, "primary");
        assert_eq!(config.guest_ip, [10, 0, 0, 2]);
        assert_eq!(config.netmask, [255, 255, 255, 0]);
        assert_eq!(config.gateway, [10, 0, 0, 1]);
        assert_eq!(config.env_vars.len(), 1);
        assert_eq!(config.env_vars[0].0, "FOO");
        assert_eq!(config.volume_mounts.len(), 1);
        assert_eq!(config.volume_mounts[0].name, "scratch");
        assert_eq!(config.dummy_ip_routes.len(), 1);
        assert_eq!(config.dummy_ip_routes[0].dummy_ip, [240, 0, 0, 45]);
        // No delegated key installed -> SVID fields empty (fail-closed).
        assert!(config.svid_cert_chain_der.is_empty());
        assert!(config.svid_private_key_der.is_empty());
    }
}
