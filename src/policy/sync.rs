// SPDX-License-Identifier: Apache-2.0
//! Full-state policy sync: desired-set diff, stale sweep.
//!
//! Ruling B: every `SagUpdate` frame is full state. The agent computes the
//! desired key set from the compiled entries, diffs against the currently
//! tracked keys, and produces insert/delete mutations. The caller applies
//! these to the eBPF maps via the Batch 4 `maps.rs` helpers.
//!
//! Version monotonicity: updates with `version <= current_version` are
//! discarded. This is the Ruling B discard mechanism — stale frames from
//! reconnect races are silently dropped.

use crate::error::AgentError;
use crate::policy::{CompiledPolicyEntry, CompiledPolicySet};
use fleetos_core::MonotonicVersion;
use fleetos_core::proto::state::SagRule as ProtoSagRule;
use fleetos_ebpf_common::{EbpfPolicyKey, EbpfPolicyValue, EbpfPolicyWildcardKey};
use fleetos_policy_compiler::compiler::{
    compile_policy_set, to_ebpf_exact_key, to_ebpf_value, to_ebpf_wildcard_key,
};
use fleetos_policy_compiler::convert::proto_rule_to_core;
use std::collections::HashSet;

/// Tracks the current state of policy entries in the eBPF maps.
///
/// The agent maintains this as a userspace mirror of what's in the kernel
/// maps. It's the source of truth for the diff computation.
#[derive(Debug, Clone)]
pub struct PolicySyncState {
    /// The current `sag_version` we've applied.
    pub current_version: u64,
    /// Exact keys currently in POLICY_EXACT (as byte arrays for hashing).
    pub exact_keys: HashSet<[u8; 40]>,
    /// Wildcard keys currently in POLICY_WILDCARD (as byte arrays for hashing).
    pub wildcard_keys: HashSet<[u8; 32]>,
}

impl PolicySyncState {
    pub fn new() -> Self {
        Self {
            current_version: 0,
            exact_keys: HashSet::new(),
            wildcard_keys: HashSet::new(),
        }
    }
}

/// Mutations to apply to the eBPF maps.
///
/// The caller iterates these and calls the Batch 4 `maps.rs` helpers
/// (`insert_policy_exact`, `insert_policy_wildcard`, etc.) to apply them.
#[derive(Clone, Default)]
pub struct PolicyMutations {
    pub insert_exact: Vec<(EbpfPolicyKey, EbpfPolicyValue)>,
    pub delete_exact: Vec<[u8; 40]>,
    pub insert_wildcard: Vec<(EbpfPolicyWildcardKey, EbpfPolicyValue)>,
    pub delete_wildcard: Vec<[u8; 32]>,
}

impl PolicyMutations {
    /// Returns true if there are no mutations to apply.
    pub fn is_empty(&self) -> bool {
        self.insert_exact.is_empty()
            && self.delete_exact.is_empty()
            && self.insert_wildcard.is_empty()
            && self.delete_wildcard.is_empty()
    }
}

/// Convert an `EbpfPolicyKey` to its byte representation for tracking.
fn exact_key_bytes(key: &EbpfPolicyKey) -> [u8; 40] {
    bytemuck::bytes_of(key)
        .try_into()
        .expect("EbpfPolicyKey is 40 bytes")
}

/// Convert an `EbpfPolicyWildcardKey` to its byte representation for tracking.
fn wildcard_key_bytes(key: &EbpfPolicyWildcardKey) -> [u8; 32] {
    bytemuck::bytes_of(key)
        .try_into()
        .expect("EbpfPolicyWildcardKey is 32 bytes")
}

/// High-level compile-and-sync entry point.
///
/// Called by the `WatchSag` handler when a new `SagUpdate` frame arrives.
/// Converts proto rules → core rules → compiled entries → mutations.
///
/// Returns `None` if the update is stale (version <= current).
pub fn compile_and_sync(
    state: &PolicySyncState,
    proto_rules: &[ProtoSagRule],
    version: u64,
    data_trust_domain: &str,
) -> Result<Option<(PolicyMutations, CompiledPolicySet)>, AgentError> {
    // Ruling B: version monotonicity check. Discard stale frames.
    if version <= state.current_version {
        tracing::debug!(
            incoming = version,
            current = state.current_version,
            "discarding stale SagUpdate"
        );
        return Ok(None);
    }

    // 1. Convert proto rules to core rules.
    let mut core_rules = Vec::with_capacity(proto_rules.len());
    for proto_rule in proto_rules {
        let core_rule = proto_rule_to_core(proto_rule)
            .map_err(|e| AgentError::Policy(format!("proto→core conversion failed: {}", e)))?;
        core_rules.push(core_rule);
    }

    // 2. Compile the full rule set.
    let monotonic_version = MonotonicVersion::new(version);
    let compiled = compile_policy_set(&core_rules, monotonic_version, data_trust_domain)
        .map_err(|e| AgentError::Policy(format!("compilation failed: {}", e)))?;

    // 3. Compute mutations.
    let mutations = compute_sync_mutations(state, &compiled);

    Ok(Some((mutations, compiled)))
}

/// Compute the diff between the desired state (compiled entries) and the
/// current state (tracked keys).
///
/// Returns insert/delete mutations. The caller applies these to the eBPF maps.
pub fn compute_sync_mutations(
    state: &PolicySyncState,
    compiled: &CompiledPolicySet,
) -> PolicyMutations {
    let mut mutations = PolicyMutations::default();

    let mut desired_exact_keys: HashSet<[u8; 40]> = HashSet::new();
    let mut desired_wildcard_keys: HashSet<[u8; 32]> = HashSet::new();

    // Build the desired key set and collect insertions.
    for entry in &compiled.entries {
        match entry {
            CompiledPolicyEntry::Exact { .. } => {
                if let Some(key) = to_ebpf_exact_key(entry) {
                    let key_bytes = exact_key_bytes(&key);
                    desired_exact_keys.insert(key_bytes);
                    if !state.exact_keys.contains(&key_bytes) {
                        let value = to_ebpf_value(entry);
                        mutations.insert_exact.push((key, value));
                    }
                }
            }
            CompiledPolicyEntry::Wildcard { .. } => {
                if let Some(key) = to_ebpf_wildcard_key(entry) {
                    let key_bytes = wildcard_key_bytes(&key);
                    desired_wildcard_keys.insert(key_bytes);
                    if !state.wildcard_keys.contains(&key_bytes) {
                        let value = to_ebpf_value(entry);
                        mutations.insert_wildcard.push((key, value));
                    }
                }
            }
        }
    }

    // Deletions: keys in current state but not in desired state.
    for key in &state.exact_keys {
        if !desired_exact_keys.contains(key) {
            mutations.delete_exact.push(*key);
        }
    }
    for key in &state.wildcard_keys {
        if !desired_wildcard_keys.contains(key) {
            mutations.delete_wildcard.push(*key);
        }
    }

    mutations
}

/// Apply mutations to the sync state after they've been applied to the eBPF maps.
///
/// Call this AFTER the mutations have been successfully applied to the kernel
/// maps. This keeps the userspace mirror in sync with the kernel.
pub fn apply_mutations_to_state(
    state: &mut PolicySyncState,
    mutations: &PolicyMutations,
    new_version: u64,
) {
    for (key, _) in &mutations.insert_exact {
        state.exact_keys.insert(exact_key_bytes(key));
    }
    for key in &mutations.delete_exact {
        state.exact_keys.remove(key);
    }
    for (key, _) in &mutations.insert_wildcard {
        state.wildcard_keys.insert(wildcard_key_bytes(key));
    }
    for key in &mutations.delete_wildcard {
        state.wildcard_keys.remove(key);
    }
    state.current_version = new_version;
}
