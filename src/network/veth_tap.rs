use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

pub struct NetworkInterfaceManager;

impl NetworkInterfaceManager {
    /// Creates a host TAP interface for Cloud-Hypervisor MicroVM network binding
    pub async fn create_tap_interface(tap_name: &str, _owner_uid: u32) -> Result<()> {
        info!(
            "Creating TAP interface '{}' for MicroVM binding...",
            tap_name
        );

        // 1. Create TAP device via ip tuntap
        let status = Command::new("ip")
            .args(["tuntap", "add", "dev", tap_name, "mode", "tap"])
            .status()
            .await
            .context("Failed to execute 'ip tuntap' command")?;

        if !status.success() {
            anyhow::bail!("Failed to create TAP interface '{}'", tap_name);
        }

        // 2. Set interface link UP
        let status = Command::new("ip")
            .args(["link", "set", "dev", tap_name, "up"])
            .status()
            .await
            .context("Failed to set TAP interface link state UP")?;

        if !status.success() {
            anyhow::bail!("Failed to bring UP TAP interface '{}'", tap_name);
        }

        info!(
            "Successfully created and activated TAP interface '{}'",
            tap_name
        );
        Ok(())
    }

    /// Creates a veth pair (host_side <-> peer_side) for namespace or bridge plumbing
    pub async fn create_veth_pair(host_veth: &str, peer_veth: &str) -> Result<()> {
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
        let _ = Command::new("ip")
            .args(["link", "set", "dev", host_veth, "up"])
            .status()
            .await;
        let _ = Command::new("ip")
            .args(["link", "set", "dev", peer_veth, "up"])
            .status()
            .await;

        info!(
            "veth pair '{}' <-> '{}' created and set UP",
            host_veth, peer_veth
        );
        Ok(())
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
