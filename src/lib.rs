// SPDX-License-Identifier: Apache-2.0
//! fleetos-agent: the worker-node daemon.
//!
//! One agent runs on every node that hosts workloads. It is the local
//! representative of the control plane and the only thing standing between
//! a workload and the network on that node.
//!
//! Module layout follows the batch execution plan. Modules are uncommented
//! as their batch lands.

#[cfg(all(feature = "dev", not(fleetos_dev)))]
compile_error!(
    "The `dev` feature is strictly for integration tests and must not be shipped. \
     Compile with `RUSTFLAGS='--cfg fleetos_dev'` to override."
);

pub mod config;
pub mod error;

// Batch 2 — Identity state & storage
// pub mod storage;
// pub mod identity;

// Batch 3 — Control client
// pub mod client;

// Batch 4 — eBPF loader lifecycle
// pub mod ebpf;

// Batch 5 — Policy boundary
// pub mod policy;

// Batch 6 — Routes & name resolution
// pub mod routes;

// Batch 7 — VSOCK attestation server
// pub mod vsock_attest;

// Batch 8 — Secrets & degraded mode
// pub mod secret;

// Batch 9 — Join flows
// pub mod join;

// Batch 10 — Workload lifecycle
// pub mod workloads;

// Batch 11 — Observability
// pub mod observability;
