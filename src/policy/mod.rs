// SPDX-License-Identifier: Apache-2.0
//! Policy subsystem: SAG → eBPF map compilation and sync.
//!
//! Ruling A is RESOLVED: the SAG→eBPF compiler lives in the shared
//! `fleetos-policy-compiler` crate. This module wires it into the agent's
//! watch loop and manages the desired-state diff against the eBPF maps.
//!
//! The compilation pipeline is:
//!   1. Proto `SagRule` → core `SagRule` (via `proto_rule_to_core`)
//!   2. Core `SagRule` → `CompiledPolicyEntry` (via `compile_policy_set`)
//!   3. `CompiledPolicyEntry` → eBPF key/value structs (via `to_ebpf_*`)
//!   4. Diff desired vs current → mutations (insert/delete)
//!   5. Caller applies mutations to eBPF maps (Batch 4 `maps.rs` helpers)

pub mod sync;

// Re-export the compiler's public surface for convenience.
pub use fleetos_policy_compiler::compiler::{
    compile_policy_set, to_ebpf_exact_key, to_ebpf_value, to_ebpf_wildcard_key,
};
pub use fleetos_policy_compiler::convert::proto_rule_to_core;
pub use fleetos_policy_compiler::{
    CompiledPolicyEntry, CompiledPolicySet, PolicyDecision, PolicyError,
};
