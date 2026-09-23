// SPDX-License-Identifier: Apache-2.0
//! HTTP GET probe: success = 2xx/3xx response.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::error::AgentError;

/// Run an HTTP GET probe. Success = 2xx/3xx response.
pub fn run_probe(path: &str, port: u32, timeout: Duration) -> Result<(), AgentError> {
    let addr = format!("127.0.0.1:{}", port);

    let mut stream = TcpStream::connect_timeout(
        &addr
            .parse()
            .map_err(|e| AgentError::Workload(format!("bad addr: {}", e)))?,
        timeout,
    )
    .map_err(|e| AgentError::Workload(format!("http probe connect failed: {}", e)))?;

    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| AgentError::Workload(format!("set_read_timeout: {}", e)))?;

    // Send minimal HTTP request.
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| AgentError::Workload(format!("http probe write failed: {}", e)))?;

    // Read response status line.
    let mut buf = [0u8; 1024];
    let n = stream
        .read(&mut buf)
        .map_err(|e| AgentError::Workload(format!("http probe read failed: {}", e)))?;

    if n == 0 {
        return Err(AgentError::Workload("http probe: empty response".into()));
    }

    // Parse status line: "HTTP/1.1 200 OK"
    let response = String::from_utf8_lossy(&buf[..n]);
    let status_line = response.lines().next().unwrap_or("");
    let status_code: u32 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if (200..400).contains(&status_code) {
        Ok(())
    } else {
        Err(AgentError::Workload(format!(
            "http probe failed with status: {}",
            status_code
        )))
    }
}
