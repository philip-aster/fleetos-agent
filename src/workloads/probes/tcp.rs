// SPDX-License-Identifier: Apache-2.0
//! TCP socket probe: success = TCP connect succeeds.

use std::net::TcpStream;
use std::time::Duration;

use crate::error::AgentError;

/// Run a TCP socket probe. Success = TCP connect succeeds.
pub fn run_probe(port: u32, timeout: Duration) -> Result<(), AgentError> {
    let addr = format!("127.0.0.1:{}", port);

    TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| AgentError::Workload(format!("bad addr: {}", e)))?,
        timeout,
    )
    .map_err(|e| AgentError::Workload(format!("tcp probe failed: {}", e)))?;

    Ok(())
}
