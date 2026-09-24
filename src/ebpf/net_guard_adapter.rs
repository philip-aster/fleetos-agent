// SPDX-License-Identifier: Apache-2.0
//! VmNetGuard adapter implementing the workloads-layer `NetGuard` trait.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aya::maps::Array;

use crate::ebpf::EbpfManager;
use crate::ebpf::programs::VmNetGuard;
use crate::error::AgentError;
use crate::workloads::NetGuard;

/// Adapter bridging the eBPF VmNetGuard to the workloads-layer NetGuard trait.
pub struct VmNetGuardAdapter {
    manager: Arc<Mutex<EbpfManager>>,
    boot_gate: Mutex<Option<Array<aya::maps::MapData, u32>>>,
    /// Live guards keyed by interface. Dropping a guard detaches its TC links.
    guards: Mutex<HashMap<String, VmNetGuard>>,
}

impl VmNetGuardAdapter {
    /// Construct the adapter, taking ownership of the BOOT_GATE map.
    pub fn new(manager: Arc<Mutex<EbpfManager>>) -> Result<Self, AgentError> {
        // Scope the MutexGuard to avoid borrow-checker conflict when moving `manager`.
        let boot_gate = {
            let mut mgr = manager.lock().unwrap();
            let map = mgr
                .ebpf
                .take_map("BOOT_GATE")
                .ok_or_else(|| AgentError::Ebpf("BOOT_GATE map missing".into()))?;
            Array::try_from(map).map_err(|e| AgentError::Ebpf(format!("BOOT_GATE: {e}")))?
        };
        Ok(Self {
            manager,
            boot_gate: Mutex::new(Some(boot_gate)),
            guards: Mutex::new(HashMap::new()),
        })
    }
}

impl NetGuard for VmNetGuardAdapter {
    fn arm(&self, interface: &str) -> Result<(), AgentError> {
        let mut mgr = self.manager.lock().unwrap();
        let mut bg = self.boot_gate.lock().unwrap();
        let boot_gate = bg
            .as_mut()
            .ok_or_else(|| AgentError::Ebpf("BOOT_GATE not available".into()))?;
        let guard = VmNetGuard::arm(&mut mgr.ebpf, interface, boot_gate)?;
        self.guards
            .lock()
            .unwrap()
            .insert(interface.to_string(), guard);
        tracing::info!(interface, "VmNetGuard armed");
        Ok(())
    }

    fn disarm(&self, interface: &str) -> Result<(), AgentError> {
        // Drop the VmNetGuard to detach its TC links.
        let _guard = self.guards.lock().unwrap().remove(interface);
        drop(_guard);

        // Set BOOT_GATE[0] = 0 to re-close the gate.
        let mut bg = self.boot_gate.lock().unwrap();
        if let Some(boot_gate) = bg.as_mut() {
            boot_gate
                .set(0, 0, 0)
                .map_err(|e| AgentError::Ebpf(format!("BOOT_GATE disarm: {e}")))?;
        }
        tracing::info!(interface, "VmNetGuard disarmed");
        Ok(())
    }
}
