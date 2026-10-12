// SPDX-License-Identifier: Apache-2.0
//! Container network namespace management (Ruling H / Phase 8.3).
//!
//! The agent owns container networking — no CNI. Per containerd workload:
//!   1. Create a netns with `ip netns add` (lives at /run/netns/<pod_id>).
//!   2. Create a veth pair; host end = gateway IP, container end moved into
//!      the workload netns with the container IP.
//!   3. Add a default route inside the netns via the gateway.
//!   4. Hand the netns path to containerd via the OCI spec.
//!
//! The container-end address is the source IP fleetos_connect4 sees, so it is
//! the key registered in SRC_IDENTITY_MAP (done by WorkloadManager::boot_pod).
//!
//! Implementation choice: shell out to `ip` via tokio::process::Command rather
//! than use rtnetlink directly. Rationale: rtnetlink's API churns significantly
//! between versions (0.14 had a fluent builder, 0.23 takes raw LinkMessages);
//! `ip` is the stable ABI surface that container runtimes use internally, and
//! the command set is small + bounded. All operations require CAP_NET_ADMIN.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use tokio::process::Command;

use crate::error::AgentError;

/// Directory where iproute2 places netns files. `ip netns add` creates files
/// here by default.
pub const NETNS_DIR: &str = "/run/netns";
/// Name of the container-side interface inside the workload netns.
const CONTAINER_IFACE: &str = "eth0";
/// Host-side veth prefix (kept short for IFNAMSIZ).
const HOST_VETH_PREFIX: &str = "fveth";

/// Netns path for a pod (matches iproute2 convention).
pub fn netns_path(pod_id: &str) -> PathBuf {
    Path::new(NETNS_DIR).join(pod_id)
}

/// Host-side veth name for a pod. Must fit IFNAMSIZ (15 usable chars).
pub fn host_veth_name(pod_id: &str) -> String {
    let suffix = if pod_id.len() > 15 - HOST_VETH_PREFIX.len() {
        format!("{:x}", fnv1a(pod_id))
    } else {
        pod_id.to_string()
    };
    let max = 15 - HOST_VETH_PREFIX.len();
    format!("{}{}", HOST_VETH_PREFIX, &suffix[..suffix.len().min(max)])
}

fn fnv1a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Create a new network namespace at /run/netns/<pod_id> via `ip netns add`.
pub async fn create_netns(pod_id: &str) -> Result<PathBuf, AgentError> {
    run_ip(&["netns", "add", pod_id]).await?;
    Ok(netns_path(pod_id))
}

/// Destroy a pod's netns via `ip netns del`. Best-effort.
pub async fn destroy_netns(pod_id: &str) -> Result<(), AgentError> {
    if !netns_path(pod_id).exists() {
        return Ok(());
    }
    // Best-effort: log but don't propagate failure so the caller still cleans
    // up the IP allocation and source identity.
    if let Err(e) = run_ip(&["netns", "del", pod_id]).await {
        tracing::warn!(pod_id, error = %e, "ip netns del failed");
    }
    Ok(())
}

/// Configure the netns: veth pair, gateway/container IPs, default route.
///
/// `container_ip` / `gateway_ip` are canonical (big-endian numeric) u32 from
/// the allocator's /30 pair.
pub async fn configure_netns(
    pod_id: &str,
    container_ip: u32,
    gateway_ip: u32,
) -> Result<(), AgentError> {
    let hveth = host_veth_name(pod_id);
    let ctr = Ipv4Addr::from(container_ip.to_be_bytes());
    let gw = Ipv4Addr::from(gateway_ip.to_be_bytes());

    // 1. Create the veth pair in the host netns.
    run_ip(&[
        "link",
        "add",
        &hveth,
        "type",
        "veth",
        "peer",
        "name",
        CONTAINER_IFACE,
    ])
    .await?;

    // 2. Assign the gateway IP to the host end (/30 point-to-point) and up it.
    let gw_cidr = format!("{gw}/30");
    run_ip(&["addr", "add", &gw_cidr, "dev", &hveth]).await?;
    run_ip(&["link", "set", &hveth, "up"]).await?;

    // 3. Move the container end into the target netns.
    run_ip(&["link", "set", CONTAINER_IFACE, "netns", pod_id]).await?;

    // 4. Inside the target netns: assign container IP, up, default route.
    let ctr_cidr = format!("{ctr}/30");
    run_ip_in(pod_id, &["addr", "add", &ctr_cidr, "dev", CONTAINER_IFACE]).await?;
    run_ip_in(pod_id, &["link", "set", CONTAINER_IFACE, "up"]).await?;
    run_ip_in(pod_id, &["route", "add", "default", "via", &gw.to_string()]).await?;

    Ok(())
}

/// Run `ip <args...>` in the host netns. Returns Ok on zero exit; Err with
/// the stderr content on non-zero exit.
async fn run_ip(args: &[&str]) -> Result<(), AgentError> {
    run_cmd("ip", args, None).await
}

/// Run `ip netns exec <ns> ip <args...>` inside the named netns.
async fn run_ip_in(ns: &str, args: &[&str]) -> Result<(), AgentError> {
    let mut full: Vec<&str> = vec!["netns", "exec", ns, "ip"];
    full.extend_from_slice(args);
    run_cmd("ip", &full, None).await
}

async fn run_cmd(
    program: &str,
    args: &[&str],
    stdin_data: Option<&[u8]>,
) -> Result<(), AgentError> {
    let mut cmd = Command::new(program);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    } else {
        cmd.stdin(Stdio::null());
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| AgentError::Workload(format!("spawn {program} {}: {e}", args.join(" "))))?;
    if let Some(data) = stdin_data {
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(data).await;
        }
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| AgentError::Workload(format!("wait {program} {}: {e}", args.join(" "))))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AgentError::Workload(format!(
            "{program} {} failed (status={}): {}",
            args.join(" "),
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}
