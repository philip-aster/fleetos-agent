pub mod liveness;
pub mod readiness;

use liveness::LivenessProbe;
use readiness::ReadinessProbe;
use std::net::SocketAddr;
use std::time::Duration;

pub struct ProbeManager;

impl ProbeManager {
    /// Executes a TCP liveness check against a workload socket
    pub async fn execute_liveness_check(addr: SocketAddr) -> bool {
        LivenessProbe::check_tcp(addr, Duration::from_secs(2))
            .await
            .unwrap_or(false)
    }

    /// Executes an HTTP readiness check against a workload path
    pub async fn execute_readiness_check(addr: SocketAddr, path: &str) -> bool {
        ReadinessProbe::check_http(addr, path, Duration::from_secs(3))
            .await
            .unwrap_or(false)
    }

    /// Executes a VSOCK liveness check against a MicroVM CID/Port
    pub async fn execute_vsock_liveness_check(cid: u32, port: u32) -> bool {
        LivenessProbe::check_vsock(cid, port, Duration::from_secs(2))
            .await
            .unwrap_or(false)
    }

    /// Executes a VSOCK readiness check against a MicroVM CID/Port
    pub async fn execute_vsock_readiness_check(cid: u32, port: u32) -> bool {
        ReadinessProbe::check_vsock(cid, port, Duration::from_secs(3))
            .await
            .unwrap_or(false)
    }
}
