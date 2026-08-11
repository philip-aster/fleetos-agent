pub mod liveness;
pub mod readiness;

use liveness::LivenessProbe;
use readiness::ReadinessProbe;
use std::net::SocketAddr;
use std::time::Duration;

pub struct ProbeManager;

impl ProbeManager {
    pub async fn execute_liveness_check(addr: SocketAddr) -> bool {
        LivenessProbe::check_tcp(addr, Duration::from_secs(2))
            .await
            .unwrap_or(false)
    }

    pub async fn execute_readiness_check(addr: SocketAddr, path: &str) -> bool {
        ReadinessProbe::check_http(addr, path, Duration::from_secs(3))
            .await
            .unwrap_or(false)
    }
}
