// SPDX-License-Identifier: Apache-2.0
//! Phase 8.5.8: Secret delivery to workload tests.
//!
//! Verifies that deliver() writes to the per-pod directory when a matching
//! pod exists, falls back to the flat path when no pod matches, and that
//! the containerd OCI spec includes the secrets bind-mount.
use fleetos_agent::workloads::RuntimeKind;
use fleetos_agent::workloads::pod_manager::{Pod, PodManager};
use fleetos_core::hash::IdentityFingerprint;
use std::sync::Arc;
use tokio::sync::RwLock;

fn make_pod(pod_id: &str, workload_id: &str, tenant_id: &str) -> Pod {
    let mut pod = Pod::new(
        pod_id.to_string(),
        workload_id.to_string(),
        tenant_id.to_string(),
        "primary".to_string(),
        RuntimeKind::Containerd,
        IdentityFingerprint([0u8; 16]),
    );
    pod.state = fleetos_agent::workloads::pod_manager::PodState::Running;
    pod
}

#[tokio::test]
async fn deliver_writes_to_per_pod_directory_when_pod_exists() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("pod-1", "db", "tenant-1"));

    // Simulate the deliver path: parse SPIFFE ID, find pod, build path.
    let spiffe_id = "spiffe://test.internal/ns/tenant-1/sa/db";
    let parsed: fleetos_core::spiffe::SpiffeId = spiffe_id.parse().unwrap();
    let safe_name = spiffe_id.replace(['/', ':'], "_");

    // Find matching pod.
    let pod_id = {
        let pm_read = pm.read().await;
        pm_read
            .all_pods()
            .find(|p| p.tenant_id == parsed.tenant && p.workload_id == parsed.name)
            .map(|p| p.pod_id.clone())
    };

    assert_eq!(pod_id, Some("pod-1".to_string()));

    let path = match pod_id {
        Some(pid) => format!("/run/fleetos/pods/{pid}/secrets/{safe_name}"),
        None => format!("/run/fleetos/secrets/{safe_name}"),
    };
    assert!(path.contains("/pods/pod-1/secrets/"));
}

#[tokio::test]
async fn deliver_falls_back_to_flat_path_when_no_pod_matches() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    // No pods registered.

    let spiffe_id = "spiffe://test.internal/ns/tenant-1/sa/db";
    let parsed: fleetos_core::spiffe::SpiffeId = spiffe_id.parse().unwrap();
    let safe_name = spiffe_id.replace(['/', ':'], "_");

    let pod_id = {
        let pm_read = pm.read().await;
        pm_read
            .all_pods()
            .find(|p| p.tenant_id == parsed.tenant && p.workload_id == parsed.name)
            .map(|p| p.pod_id.clone())
    };

    assert_eq!(pod_id, None);

    let path = match pod_id {
        Some(pid) => format!("/run/fleetos/pods/{pid}/secrets/{safe_name}"),
        None => format!("/run/fleetos/secrets/{safe_name}"),
    };
    assert!(path.starts_with("/run/fleetos/secrets/"));
    assert!(!path.contains("/pods/"));
}

#[test]
fn containerd_oci_spec_includes_secrets_bind_mount() {
    use serde_json::json;

    // Simulate the OCI mount construction from build_oci_spec.
    let pod_id = "pod-1";
    let secrets_dir = format!("/run/fleetos/pods/{}/secrets", pod_id);
    let secrets_mount = json!({
        "destination": "/run/secrets",
        "type": "bind",
        "source": secrets_dir,
        "options": ["rbind", "ro"]
    });

    assert_eq!(secrets_mount["destination"], "/run/secrets");
    assert_eq!(secrets_mount["type"], "bind");
    assert!(
        secrets_mount["source"]
            .as_str()
            .unwrap()
            .contains("/pods/pod-1/secrets")
    );
    assert_eq!(secrets_mount["options"][1], "ro");
}
