// SPDX-License-Identifier: Apache-2.0
//! Identity management: node SVID lifecycle, secret-sequence replay
//! protection, and TPM-sealed sensitive-key storage.

pub mod degraded;
pub mod keystore;
pub mod sequences;
pub mod svid;
