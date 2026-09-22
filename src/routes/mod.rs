// SPDX-License-Identifier: Apache-2.0
//! Routes subsystem: dummy-IP route table management and name resolution.
//!
//! Handles the `WatchRoutes` stream from fleetos-control:
//! - Converts `RouteEntry` protos → eBPF `DUMMY_IP_ROUTE_MAP` entries
//! - Tracks `LOCAL_WORKLOADS` for same-node fast path
//! - Provides `SRC_IDENTITY_MAP` registration hooks for workload lifecycle
//! - Builds `/etc/hosts` content for workload name resolution (Ruling E)

pub mod hosts;
pub mod table;
