// SPDX-License-Identifier: Apache-2.0
//! Integration test: Route sync pipeline (Phase 7.2)
//!
//! Tests process_route_update and apply_mutations_to_state from routes::table.
//! Verifies RouteSyncState is correctly updated when RouteUpdates are applied,
//! stale updates are discarded, and route removals produce deletions.

use fleetos_agent::routes::table::{
    RouteMutation, RouteSyncState, apply_mutations_to_state, process_route_update,
};
use fleetos_core::proto::state::{RouteEntry, RouteUpdate};
use fleetos_core::spiffe::{IdKind, SpiffeId};

fn own_node_spiffe_id() -> SpiffeId {
    SpiffeId::new("test.internal", "system", IdKind::Node, "agent-1")
}

fn dest_svid(service: &str) -> String {
    format!("spiffe://test.internal/ns/tenant-1/sa/{}", service)
}

fn make_route(
    dest_service: &str,
    dest_role: &str,
    target_agent: &str,
    dummy_ip: u32,
) -> RouteEntry {
    RouteEntry {
        destination_svid: dest_svid(dest_service),
        destination_role: dest_role.to_string(),
        target_agent_svid: target_agent.to_string(),
        dummy_ip,
        source_spiffe_ids: vec![],
    }
}

#[test]
fn first_apply_produces_insert_mutations() {
    let state = RouteSyncState::new();
    let own = own_node_spiffe_id();
    let own_str = own.to_string();

    let update = RouteUpdate {
        version: 1,
        routes: vec![
            make_route("db", "primary", &own_str, 0xF000_0001),
            make_route("auth", "primary", &own_str, 0xF000_0002),
        ],
    };

    let result = process_route_update(&state, &update, &own).expect("process_route_update failed");
    assert!(result.is_some(), "first apply must produce mutations");

    let mutations = result.unwrap();
    let inserts = mutations
        .mutations
        .iter()
        .filter(|m| matches!(m, RouteMutation::InsertRoute { .. }))
        .count();
    assert_eq!(
        inserts, 2,
        "two routes should produce two InsertRoute mutations"
    );

    let local_workloads = mutations
        .mutations
        .iter()
        .filter(|m| matches!(m, RouteMutation::AddLocalWorkload { .. }))
        .count();
    assert_eq!(
        local_workloads, 2,
        "both routes target the own node, so two AddLocalWorkload mutations expected"
    );
}

#[test]
fn stale_route_update_is_discarded() {
    let mut state = RouteSyncState::new();
    let own = own_node_spiffe_id();
    let own_str = own.to_string();

    // Apply v1.
    let update_v1 = RouteUpdate {
        version: 1,
        routes: vec![make_route("db", "primary", &own_str, 0xF000_0001)],
    };
    let mutations_v1 = process_route_update(&state, &update_v1, &own)
        .expect("v1 apply failed")
        .expect("v1 must produce mutations");
    apply_mutations_to_state(&mut state, &mutations_v1, 1);
    assert_eq!(state.current_version, 1);

    // Stale update (version 0 <= current 1) must be discarded.
    let stale = RouteUpdate {
        version: 0,
        routes: vec![],
    };
    let stale_result = process_route_update(&state, &stale, &own).expect("stale check failed");
    assert!(stale_result.is_none(), "stale update must return None");

    // Same version (1 <= 1) must also be discarded.
    let same_version = RouteUpdate {
        version: 1,
        routes: vec![],
    };
    let same_result =
        process_route_update(&state, &same_version, &own).expect("same-version check failed");
    assert!(
        same_result.is_none(),
        "same-version update must return None"
    );
}

#[test]
fn route_removal_produces_delete_mutations() {
    let mut state = RouteSyncState::new();
    let own = own_node_spiffe_id();
    let own_str = own.to_string();

    // Apply v1: two routes.
    let update_v1 = RouteUpdate {
        version: 1,
        routes: vec![
            make_route("db", "primary", &own_str, 0xF000_0001),
            make_route("auth", "primary", &own_str, 0xF000_0002),
        ],
    };
    let mutations_v1 = process_route_update(&state, &update_v1, &own)
        .expect("v1 apply failed")
        .expect("v1 must produce mutations");
    apply_mutations_to_state(&mut state, &mutations_v1, 1);
    assert_eq!(state.dummy_ip_keys.len(), 2);
    assert_eq!(state.local_workload_fps.len(), 2);

    // Apply v2: only one route (auth removed).
    let update_v2 = RouteUpdate {
        version: 2,
        routes: vec![make_route("db", "primary", &own_str, 0xF000_0001)],
    };
    let mutations_v2 = process_route_update(&state, &update_v2, &own)
        .expect("v2 apply failed")
        .expect("v2 must produce mutations");

    let deletes = mutations_v2
        .mutations
        .iter()
        .filter(|m| matches!(m, RouteMutation::DeleteRoute { .. }))
        .count();
    assert_eq!(
        deletes, 1,
        "removed route must produce one DeleteRoute mutation"
    );

    let local_removes = mutations_v2
        .mutations
        .iter()
        .filter(|m| matches!(m, RouteMutation::RemoveLocalWorkload { .. }))
        .count();
    assert_eq!(
        local_removes, 1,
        "removed local route must produce one RemoveLocalWorkload mutation"
    );

    apply_mutations_to_state(&mut state, &mutations_v2, 2);
    assert_eq!(state.current_version, 2);
    assert_eq!(
        state.dummy_ip_keys.len(),
        1,
        "one route remains after removal"
    );
    assert_eq!(state.local_workload_fps.len(), 1);
}
