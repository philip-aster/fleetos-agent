use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::{info, warn};

pub struct NetworkInterfaceManager;

impl NetworkInterfaceManager {
    /// Helper to fetch the kernel `ifindex` for a network interface name from sysfs
    pub async fn get_ifindex(iface_name: &str) -> Result<u32> {
        let sysfs_path = format!("/sys/class/net/{}/ifindex", iface_name);
        let content = tokio::fs::read_to_string(&sysfs_path)
            .await
            .with_context(|| format!("Failed to read interface index from {}", sysfs_path))?;

        let ifindex: u32 = content
            .trim()
            .parse()
            .with_context(|| format!("Failed to parse ifindex for interface '{}'", iface_name))?;

        Ok(ifindex)
    }

    /// Creates a host TAP interface owned by `owner_uid` for Cloud-Hypervisor MicroVM binding
    /// Returns the kernel `ifindex` of the created TAP device.
    pub async fn create_tap_interface(tap_name: &str, owner_uid: u32) -> Result<u32> {
        info!(
            "Creating TAP interface '{}' (Owner UID: {}) for MicroVM binding...",
            tap_name, owner_uid
        );

        // If interface already exists from a prior unclean shutdown, clean it up first
        if Path::new(&format!("/sys/class/net/{}", tap_name)).exists() {
            warn!(
                "TAP interface '{}' already exists. Cleaning up stale device...",
                tap_name
            );
            let _ = Self::delete_interface(tap_name).await;
        }

        // 1. Create TAP device via ip tuntap with explicit user ownership
        let uid_str = owner_uid.to_string();
        let status = Command::new("ip")
            .args([
                "tuntap", "add", "dev", tap_name, "mode", "tap", "user", &uid_str,
            ])
            .status()
            .await
            .context("Failed to execute 'ip tuntap' command")?;

        if !status.success() {
            anyhow::bail!(
                "Failed to create TAP interface '{}' with owner UID {}",
                tap_name,
                owner_uid
            );
        }

        // 2. Set interface link UP
        let status = Command::new("ip")
            .args(["link", "set", "dev", tap_name, "up"])
            .status()
            .await
            .context("Failed to set TAP interface link state UP")?;

        if !status.success() {
            let _ = Self::delete_interface(tap_name).await;
            anyhow::bail!("Failed to bring UP TAP interface '{}'", tap_name);
        }

        // 3. Query system ifindex for eBPF DEVMAP registration
        let ifindex = Self::get_ifindex(tap_name).await?;

        info!(
            "Successfully created and activated TAP interface '{}' (ifindex: {})",
            tap_name, ifindex
        );
        Ok(ifindex)
    }

    /// Creates a veth pair (host_side <-> peer_side) for namespace or bridge plumbing
    pub async fn create_veth_pair(host_veth: &str, peer_veth: &str) -> Result<(u32, u32)> {
        info!("Creating veth pair: '{}' <-> '{}'", host_veth, peer_veth);

        let status = Command::new("ip")
            .args([
                "link", "add", host_veth, "type", "veth", "peer", "name", peer_veth,
            ])
            .status()
            .await
            .context("Failed to create veth pair")?;

        if !status.success() {
            anyhow::bail!("Failed to create veth pair '{}'/'{}'", host_veth, peer_veth);
        }

        // Bring both ends UP
        let status_host = Command::new("ip")
            .args(["link", "set", "dev", host_veth, "up"])
            .status()
            .await;

        let status_peer = Command::new("ip")
            .args(["link", "set", "dev", peer_veth, "up"])
            .status()
            .await;

        if let (Ok(h), Ok(p)) = (status_host, status_peer) {
            if !h.success() || !p.success() {
                let _ = Self::delete_interface(host_veth).await;
                anyhow::bail!(
                    "Failed to set veth links UP for '{}'/'{}'",
                    host_veth,
                    peer_veth
                );
            }
        }

        let host_ifindex = Self::get_ifindex(host_veth).await?;
        let peer_ifindex = Self::get_ifindex(peer_veth).await?;

        info!(
            "veth pair '{}' (ifindex {}) <-> '{}' (ifindex {}) created and set UP",
            host_veth, host_ifindex, peer_veth, peer_ifindex
        );
        Ok((host_ifindex, peer_ifindex))
    }

    /// Deletes a TAP or veth interface from the host network stack
    pub async fn delete_interface(iface_name: &str) -> Result<()> {
        info!("Tearing down network interface '{}'...", iface_name);

        let status = Command::new("ip")
            .args(["link", "delete", iface_name])
            .status()
            .await
            .context("Failed to delete network interface")?;

        if !status.success() {
            warn!(
                "Failed to delete network interface '{}' (may already be removed)",
                iface_name
            );
        } else {
            info!("Successfully deleted interface '{}'", iface_name);
        }

        Ok(())
    }
}
