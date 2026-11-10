// SPDX-License-Identifier: Apache-2.0
//! Phase 8.8: wiring watch-loop pure-logic tests.
//!
//! Tests the pure functions in wiring.rs that don't require a live
//! ControlPlaneClient: reevaluate_router_connected, mark_all_pods_policy_enforced,
//! and route_to_dummy_ip_config.
//!
//! The full watch-loop runners (run_sag_watch, run_routes_watch, etc.) are
//! covered by the integration tests in watch_reconnect.rs and
//! route_sync_integration.rs.
use fleetos_agent::workloads::RuntimeKind;
use fleetos_agent::workloads::pod_manager::{Pod, PodManager};
use fleetos_core::hash::IdentityFingerprint;
use fleetos_core::proto::state::RouteEntry;
use std::sync::Arc;
use tokio::sync::RwLock;

fn make_pod(pod_id: &str, workload_id: &str, tenant_id: &str) -> Pod {
    let mut pod = Pod::new(
        pod_id.to_string(),
        workload_id.to_string(),
        tenant_id.to_string(),
        "primary".to_string(),
        RuntimeKind::CloudHypervisor,
        IdentityFingerprint([7; 16]),
    );
    pod.state = fleetos_agent::workloads::pod_manager::PodState::Running;
    pod
}

fn make_route(dest_svid: &str, dest_role: &str, dummy_ip: u32, sources: Vec<String>) -> RouteEntry {
    RouteEntry {
        destination_svid: dest_svid.to_string(),
        destination_role: dest_role.to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/node-1".to_string(),
        dummy_ip,
        source_spiffe_ids: sources,
    }
}

// --- reevaluate_router_connected ---

#[tokio::test]
async fn pod_with_routed_dependency_is_connected() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("web-pod", "web", "tenant-1"));
    let routes = vec![make_route(
        "spiffe://test.internal/ns/tenant-1/sa/db",
        "primary",
        0xF000_0001,
        vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    )];
    fleetos_agent::wiring::reevaluate_router_connected(&pm, &routes, "test.internal").await;
    assert!(pm.read().await.get_pod("web-pod").unwrap().router_connected);
}

#[tokio::test]
async fn pod_with_unrouted_dependency_is_disconnected() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("web-pod", "web", "tenant-1"));
    let routes = vec![make_route(
        "spiffe://test.internal/ns/tenant-1/sa/db",
        "primary",
        0, // unrouted sentinel
        vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    )];
    fleetos_agent::wiring::reevaluate_router_connected(&pm, &routes, "test.internal").await;
    assert!(!pm.read().await.get_pod("web-pod").unwrap().router_connected);
}

#[tokio::test]
async fn pod_with_no_dependencies_is_trivially_connected() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("lonely-pod", "lonely", "tenant-1"));
    let routes = vec![make_route(
        "spiffe://test.internal/ns/tenant-1/sa/db",
        "primary",
        0xF000_0001,
        vec!["spiffe://test.internal/ns/tenant-1/sa/other".to_string()],
    )];
    fleetos_agent::wiring::reevaluate_router_connected(&pm, &routes, "test.internal").await;
    assert!(
        pm.read()
            .await
            .get_pod("lonely-pod")
            .unwrap()
            .router_connected
    );
}

#[tokio::test]
async fn empty_route_set_all_pods_connected() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("web-pod", "web", "tenant-1"));
    fleetos_agent::wiring::reevaluate_router_connected(&pm, &[], "test.internal").await;
    assert!(pm.read().await.get_pod("web-pod").unwrap().router_connected);
}

#[tokio::test]
async fn route_removal_flips_connected_to_false() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("web-pod", "web", "tenant-1"));
    // First: routed.
    let routed = vec![make_route(
        "spiffe://test.internal/ns/tenant-1/sa/db",
        "primary",
        0xF000_0001,
        vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    )];
    fleetos_agent::wiring::reevaluate_router_connected(&pm, &routed, "test.internal").await;
    assert!(pm.read().await.get_pod("web-pod").unwrap().router_connected);
    // Then: unrouted (dummy_ip = 0).
    let unrouted = vec![make_route(
        "spiffe://test.internal/ns/tenant-1/sa/db",
        "primary",
        0,
        vec!["spiffe://test.internal/ns/tenant-1/sa/web".to_string()],
    )];
    fleetos_agent::wiring::reevaluate_router_connected(&pm, &unrouted, "test.internal").await;
    assert!(!pm.read().await.get_pod("web-pod").unwrap().router_connected);
}

// --- mark_all_pods_policy_enforced ---

#[tokio::test]
async fn policy_enforced_set_on_all_pods() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    pm.write()
        .await
        .add_pod(make_pod("web-pod", "web", "tenant-1"));
    pm.write()
        .await
        .add_pod(make_pod("db-pod", "db", "tenant-1"));
    fleetos_agent::wiring::mark_all_pods_policy_enforced(&pm).await;
    let pm_read = pm.read().await;
    assert!(pm_read.get_pod("web-pod").unwrap().policy_enforced);
    assert!(pm_read.get_pod("db-pod").unwrap().policy_enforced);
}

#[tokio::test]
async fn policy_enforced_on_empty_manager_is_noop() {
    let pm = Arc::new(RwLock::new(PodManager::new()));
    fleetos_agent::wiring::mark_all_pods_policy_enforced(&pm).await;
    assert!(pm.read().await.is_empty());
}
