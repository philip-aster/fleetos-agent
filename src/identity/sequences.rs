// SPDX-License-Identifier: Apache-2.0
//! Secret-sequence replay protection (S-10).
//!
//! Every sealed secret carries a `(target_spiffe_id, svid_version, sequence)`
//! triple. A secret is accepted only if its sequence is strictly greater than
//! the last one we saw for that `(target, svid_version)` pair. Equal or lower
//! is rejected as a replay.
//!
//! Fail-closed: if we have no record for a pair we accept the first secret we
//! see (sequence ≥ 1) but reject anything at sequence 0. Once a record exists,
//! only strictly-newer sequences pass.

use crate::error::AgentError;
use crate::storage::Storage;

/// Build the storage key for a `(target, svid_version)` pair.
fn sequence_key(target: &str, svid_version: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(target.len() + 1 + 8);
    key.extend_from_slice(target.as_bytes());
    key.push(0x00); // separator
    key.extend_from_slice(&svid_version.to_le_bytes());
    key
}

/// Check whether an incoming secret sequence is acceptable, and if so,
/// record it. Returns `true` if the secret should be processed, `false`
/// if it must be dropped as a replay.
///
/// This is fail-closed: any ambiguity rejects.
pub fn check_and_record(
    storage: &Storage,
    target: &str,
    svid_version: u64,
    incoming_sequence: u64,
) -> Result<bool, AgentError> {
    // Sequence 0 is never valid.
    if incoming_sequence == 0 {
        return Ok(false);
    }

    let key = sequence_key(target, svid_version);

    let existing = storage
        .sequences
        .get(key.as_slice())
        .map_err(AgentError::Storage)?;

    let last_seen: u64 = match existing {
        Some(bytes) if bytes.len() >= 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            u64::from_le_bytes(buf)
        }
        _ => 0, // no prior record
    };

    if incoming_sequence <= last_seen {
        // Replay or stale duplicate. Drop it.
        return Ok(false);
    }

    // Strictly newer. Record it and accept.
    storage
        .sequences
        .insert(key.as_slice(), &incoming_sequence.to_le_bytes())
        .map_err(AgentError::Storage)?;

    Ok(true)
}

/// Return the last recorded sequence for a `(target, svid_version)` pair,
/// or `None` if we have never seen one. Useful for diagnostics.
pub fn last_seen(
    storage: &Storage,
    target: &str,
    svid_version: u64,
) -> Result<Option<u64>, AgentError> {
    let key = sequence_key(target, svid_version);
    let raw = storage
        .sequences
        .get(key.as_slice())
        .map_err(AgentError::Storage)?;

    Ok(match raw {
        Some(bytes) if bytes.len() >= 8 => {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&bytes[..8]);
            Some(u64::from_le_bytes(buf))
        }
        _ => None,
    })
}
