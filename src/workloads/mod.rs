// SPDX-License-Identifier: Apache-2.0
//! Workload lifecycle management: reconcile, pod management, probes, runtime adapters.
//!
//! The agent reconciles desired state from `WatchSchedule` against running
//! workloads. Full-state reconcile is the eviction mechanism: pods absent
//! from the desired frame are terminated with grace periods.

pub mod containerd;
pub mod env;
pub mod lifecycle;
pub mod microvm;
pub mod pod_manager;
pub mod probes;
pub mod reconciler;
pub mod status;
pub mod volumes;

use crate::error::AgentError;
use fleetos_core::proto::state::WorkloadAssignment;
use fleetos_core::proto::workload::PodSpec;

/// Runtime kind for a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuntimeKind {
    Containerd,
    CloudHypervisor,
}

impl TryFrom<i32> for RuntimeKind {
    type Error = AgentError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RuntimeKind::Containerd),
            1 => Ok(RuntimeKind::CloudHypervisor),
            _ => Err(AgentError::Workload(format!("unknown runtime: {}", value))),
        }
    }
}

impl TryFrom<&str> for RuntimeKind {
    type Error = AgentError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "containerd" => Ok(RuntimeKind::Containerd),
            "cloud-hypervisor" | "cloud_hypervisor" => Ok(RuntimeKind::CloudHypervisor),
            _ => Err(AgentError::Workload(format!("unknown runtime: {}", value))),
        }
    }
}

/// A workload assignment enriched with the full PodSpec.
#[derive(Debug, Clone)]
pub struct WorkloadSpec {
    pub workload_id: String,
    pub runtime: RuntimeKind,
    pub image: String,
    pub role: String,
    pub pod_spec: Option<PodSpec>,
    pub hostname: String,
}

impl WorkloadSpec {
    /// Convert a proto WorkloadAssignment into our internal representation.
    pub fn from_assignment(assignment: &WorkloadAssignment) -> Result<Self, AgentError> {
        let runtime = RuntimeKind::try_from(assignment.runtime.as_str())?;
        Ok(Self {
            workload_id: assignment.workload_id.clone(),
            runtime,
            image: assignment.image.clone(),
            role: assignment.role.clone(),
            pod_spec: assignment.pod_spec.clone(),
            hostname: assignment.hostname.clone(),
        })
    }

    /// Get the runtime kind.
    pub fn runtime(&self) -> RuntimeKind {
        self.runtime
    }

    /// Get the image.
    pub fn image(&self) -> &str {
        &self.image
    }

    /// Get the role.
    pub fn role(&self) -> &str {
        &self.role
    }
}
