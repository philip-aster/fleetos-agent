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

pub mod identity;
pub mod storage;

pub mod client;

pub mod ebpf;

pub mod policy;

pub mod routes;

pub mod vsock_attest;

pub mod secret;

// Batch 9 — Join flows
// pub mod join;

// Batch 10 — Workload lifecycle
// pub mod workloads;

// Batch 11 — Observability
// pub mod observability;
