// SPDX-License-Identifier: Apache-2.0
//! Phase 8.8: /etc/hosts injection builder correctness (Ruling E).
//!
//! Verifies build_hosts_entries, format_hosts_file, and build_hosts_content
//! against the canonical hostname convention owned by fleetos_core::naming.
//!
//! Pure computation tests — no eBPF, no gRPC, no storage.
use fleetos_agent::routes::hosts::{
    HostsEntry, build_hosts_content, build_hosts_entries, format_hosts_file,
};
use fleetos_core::proto::state::RouteEntry;

fn make_route(dest_svid: &str, dest_role: &str, dummy_ip: u32) -> RouteEntry {
    RouteEntry {
        destination_svid: dest_svid.to_string(),
        destination_role: dest_role.to_string(),
        target_agent_svid: "spiffe://test.internal/ns/system/node/agent-1".to_string(),
        dummy_ip,
        source_spiffe_ids: vec![],
    }
}

// --- build_hosts_entries ---

#[test]
fn produces_correct_hostname_and_ip() {
    let routes = vec![make_route(
        "spiffe://fleet.example.internal/ns/acme/sa/db",
        "primary",
        0xF000_002D, // 240.0.0.45
    )];
    let entries = build_hosts_entries(&routes, "fleet.example.internal").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].ip, "240.0.0.45");
    assert_eq!(
        entries[0].hostname,
        "db.primary.acme.svc.fleet.example.internal"
    );
}

#[test]
fn skips_empty_role_wildcard_routes() {
    let routes = vec![make_route(
        "spiffe://test.internal/ns/acme/sa/db",
        "",
        0xF000_0001,
    )];
    let entries = build_hosts_entries(&routes, "test.internal").unwrap();
    assert!(entries.is_empty(), "empty role routes must be skipped");
}

#[test]
fn multiple_routes_produce_multiple_entries() {
    let routes = vec![
        make_route(
            "spiffe://test.internal/ns/acme/sa/db",
            "primary",
            0xF000_0001,
        ),
        make_route(
            "spiffe://test.internal/ns/acme/sa/web",
            "replica",
            0xF000_0002,
        ),
        make_route(
            "spiffe://test.internal/ns/beta/sa/cache",
            "primary",
            0xF000_0003,
        ),
    ];
    let entries = build_hosts_entries(&routes, "test.internal").unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].hostname, "db.primary.acme.svc.test.internal");
    assert_eq!(entries[1].hostname, "web.replica.acme.svc.test.internal");
    assert_eq!(entries[2].hostname, "cache.primary.beta.svc.test.internal");
}

#[test]
fn rejects_invalid_spiffe_id() {
    let routes = vec![make_route("not-a-valid-spiffe-id", "primary", 0xF000_0001)];
    let result = build_hosts_entries(&routes, "test.internal");
    assert!(result.is_err());
}

#[test]
fn empty_routes_produce_empty_entries() {
    let entries = build_hosts_entries(&[], "test.internal").unwrap();
    assert!(entries.is_empty());
}

// --- format_hosts_file ---

#[test]
fn includes_header_and_localhost() {
    let entries = vec![HostsEntry {
        ip: "240.0.0.45".to_string(),
        hostname: "db.primary.acme.svc.fleet.example.internal".to_string(),
    }];
    let content = format_hosts_file(&entries);
    assert!(content.contains("# /etc/hosts"));
    assert!(content.contains("127.0.0.1\tlocalhost"));
    assert!(content.contains("::1\tlocalhost"));
}

#[test]
fn includes_fleetos_section_with_entries() {
    let entries = vec![
        HostsEntry {
            ip: "240.0.0.1".into(),
            hostname: "db.primary.acme.svc.test.internal".into(),
        },
        HostsEntry {
            ip: "240.0.0.2".into(),
            hostname: "web.replica.acme.svc.test.internal".into(),
        },
    ];
    let content = format_hosts_file(&entries);
    assert!(content.contains("# FleetOS service resolution (Ruling E)"));
    assert!(content.contains("240.0.0.1\tdb.primary.acme.svc.test.internal"));
    assert!(content.contains("240.0.0.2\tweb.replica.acme.svc.test.internal"));
}

#[test]
fn empty_entries_omit_fleetos_section() {
    let content = format_hosts_file(&[]);
    assert!(!content.contains("# FleetOS service resolution"));
    assert!(content.contains("127.0.0.1\tlocalhost"));
}

// --- build_hosts_content (convenience) ---

#[test]
fn combines_entries_and_format() {
    let routes = vec![make_route(
        "spiffe://test.internal/ns/acme/sa/db",
        "primary",
        0xF000_002D,
    )];
    let content = build_hosts_content(&routes, "test.internal").unwrap();
    assert!(content.contains("240.0.0.45\tdb.primary.acme.svc.test.internal"));
    assert!(content.contains("127.0.0.1\tlocalhost"));
}

// --- Canonical hostname convention (CR-CORE-7) ---

#[test]
fn hostname_follows_canonical_convention() {
    let routes = vec![make_route(
        "spiffe://fleet.example.internal/ns/my-tenant/sa/my-service",
        "my-role",
        0xF000_0001,
    )];
    let entries = build_hosts_entries(&routes, "fleet.example.internal").unwrap();
    assert_eq!(
        entries[0].hostname,
        "my-service.my-role.my-tenant.svc.fleet.example.internal"
    );
}

#[test]
fn dummy_ip_formats_as_dotted_quad() {
    let routes = vec![make_route(
        "spiffe://test.internal/ns/t/sa/s",
        "r",
        0xF000_00FF, // 240.0.0.255
    )];
    let entries = build_hosts_entries(&routes, "test.internal").unwrap();
    assert_eq!(entries[0].ip, "240.0.0.255");
}
