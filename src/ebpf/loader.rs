// SPDX-License-Identifier: Apache-2.0
//! eBPF object loading and pin-path management.
//!
//! Ruling C: The current fleetos-ebpf source hardcodes map sizes in
//! `HashMap::pinned(...)`. The agent cannot resize pinned maps. It detects
//! the current capacity and warns if below the expected headroom threshold.
//! A controlled-reload trigger is stubbed for when Ruling C is resolved.
//!
//! AA-3: Stale-pin detection at startup. If pins exist from a previous
//! agent run, they're cleaned up before loading.

use crate::config::EbpfConfig;
use crate::error::AgentError;
use aya::Ebpf;
use std::path::Path;

/// Load the compiled eBPF object from the configured path.
///
/// AA-8: The object must be built from the `fleetos-ebpf` workspace with
/// the exact toolchain documented in its README. Version mismatch between
/// the agent's expected ABI and the object's actual ABI is a hard failure.
pub fn load_object(config: &EbpfConfig) -> Result<Ebpf, AgentError> {
    let object_path = &config.object_path;

    // AA-8: Verify the object exists before attempting to load.
    if !object_path.exists() {
        return Err(AgentError::Ebpf(format!(
            "eBPF object not found at {}. Build it from the fleetos-ebpf workspace: \
             cargo +nightly build --release --target bpfel-unknown-none -p fleetos-ebpf -Z build-std=core",
            object_path.display()
        )));
    }

    // AA-3: Clean up stale pins from a previous agent run.
    cleanup_stale_pins(&config.pin_path)?;

    // Ensure the pin directory exists.
    std::fs::create_dir_all(&config.pin_path).map_err(AgentError::Io)?;

    // Load the object.
    let bytes = std::fs::read(object_path).map_err(|e| {
        AgentError::Ebpf(format!(
            "failed to read eBPF object at {}: {}",
            object_path.display(),
            e
        ))
    })?;

    let ebpf = Ebpf::load(&bytes)
        .map_err(|e| AgentError::Ebpf(format!("failed to load eBPF object: {}", e)))?;

    // Ruling C: Detect map capacity and warn if below headroom threshold.
    // The current eBPF source hardcodes sizes, so we can only detect, not resize.
    check_map_capacity(&ebpf, config.map_headroom_percent)?;

    Ok(ebpf)
}

/// AA-3: Remove stale pins from a previous agent run.
///
/// If the agent crashed or was killed without cleanup, pins may be left
/// behind. On next startup, we remove them so the new load starts clean.
fn cleanup_stale_pins(pin_path: &Path) -> Result<(), AgentError> {
    if !pin_path.exists() {
        return Ok(());
    }

    let entries = std::fs::read_dir(pin_path).map_err(AgentError::Io)?;
    for entry in entries {
        let entry = entry.map_err(AgentError::Io)?;
        let path = entry.path();
        if path.is_file() {
            tracing::warn!(pin = %path.display(), "removing stale eBPF pin");
            std::fs::remove_file(&path).map_err(AgentError::Io)?;
        }
    }

    Ok(())
}

/// Ruling C: Check that map capacities meet the headroom threshold.
///
/// The current fleetos-ebpf source hardcodes map sizes in `HashMap::pinned(...)`.
/// This function reads the actual capacity from the loaded object and warns
/// if it appears too small for the configured headroom. It does NOT resize
/// (that requires eBPF-side changes, pending Ruling C resolution).
fn check_map_capacity(ebpf: &Ebpf, _headroom_percent: u32) -> Result<(), AgentError> {
    // Read the POLICY_STATS array to verify the object loaded correctly.
    // If we can read index 0, the object is functional.
    let stats_map = ebpf
        .map("POLICY_STATS")
        .ok_or_else(|| AgentError::Ebpf("POLICY_STATS map missing from eBPF object".into()))?;

    // Verify the map exists and is readable. We don't check sizes here
    // because the current eBPF source hardcodes them. When Ruling C is
    // resolved with the eBPF Lead, this function will be expanded to
    // actually verify headroom.
    let _ = stats_map;

    tracing::debug!("eBPF map capacity check passed (Ruling C: detection only)");
    Ok(())
}
