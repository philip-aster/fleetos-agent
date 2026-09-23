// SPDX-License-Identifier: Apache-2.0
//! Exec probe: run a command, success = exit code 0.

use std::process::Command;
use std::time::Duration;

use crate::error::AgentError;

/// Run an exec probe. Success = exit code 0.
pub fn run_probe(command: &[String], _timeout: Duration) -> Result<(), AgentError> {
    if command.is_empty() {
        return Err(AgentError::Workload("empty exec command".into()));
    }

    let output = Command::new(&command[0])
        .args(&command[1..])
        .output()
        .map_err(|e| AgentError::Workload(format!("exec probe failed: {}", e)))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(AgentError::Workload(format!(
            "exec probe failed with exit code: {:?}",
            output.status.code()
        )))
    }
}
