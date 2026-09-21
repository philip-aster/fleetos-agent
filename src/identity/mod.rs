// SPDX-License-Identifier: Apache-2.0
//! Identity management: node SVID lifecycle, secret-sequence replay
//! protection, and TPM-sealed sensitive-key storage.

pub mod keystore;
pub mod sequences;
pub mod svid;
// pub mod degraded; // Batch 8 — DelegatedSigningKey lifecycle
