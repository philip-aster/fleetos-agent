use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::time::sleep;

use fleetos_agent::runtime::RuntimeDriver;
use fleetos_agent::workload_sync::WorkloadSyncWorker;
use fleetos_control::test_helpers::spawn_test_control_plane;
use fleetos_core::proto::state::{PutRequest, state_service_client::StateServiceClient};
use fleetos_core::{
    CloudHypervisorConfig, ContainerSpec, PodRole, PodSpec, QosClass, ResourceRequirements,
    RestartPolicy, RuntimeEngine,
};

#[tokio::test]
async fn test_workload_sync_receives_pod_dispatch() -> Result<()> {
    let addr: SocketAddr = "127.0.0.1:50055".parse()?;
    let control_plane_url = format!("http://{}", addr);
    let node_id = "test-node-1".to_string();

    // 1. Spawn Control Plane using fleetos-control test helper
    spawn_test_control_plane(addr).await?;

    // 2. Instantiate RuntimeDriver & WorkloadSyncWorker
    let runtime = Arc::new(RuntimeDriver::new());
    let worker = WorkloadSyncWorker::new(control_plane_url.clone(), node_id.clone(), runtime);

    // 3. Spawn WorkloadSyncWorker in background
    tokio::spawn(async move {
        worker.run_sync_loop().await;
    });

    sleep(Duration::from_millis(300)).await;

    // 4. Connect gRPC Client to control plane and schedule a Pod
    let mut client = StateServiceClient::connect(control_plane_url).await?;

    let test_pod = PodSpec {
        id: "pod-101".to_string(),
        name: "test-microvm-workload".to_string(),
        namespace: "default".to_string(),
        role: PodRole::default(),
        runtime: RuntimeEngine::CloudHypervisor(CloudHypervisorConfig::default()),
        labels: HashMap::new(),
        annotations: HashMap::new(),
        qos: QosClass::default(),
        containers: vec![ContainerSpec {
            name: "main".to_string(),
            image: "alpine:latest".to_string(),
            command: vec!["/bin/sh".to_string()],
            args: vec![],
            env: HashMap::new(),
            volume_mounts: vec![],
            resources: ResourceRequirements {
                cpu_shares: Some(512),
                memory_limit_mb: Some(1024),
            },
        }],
        volumes: vec![],
        restart_policy: RestartPolicy::Always,
    };

    let pod_key = format!("/pods/{}/pod-101", node_id);
    let pod_bytes = serde_json::to_vec(&test_pod)?;

    client
        .put(PutRequest {
            key: pod_key.into_bytes(),
            value: pod_bytes,
        })
        .await?;

    sleep(Duration::from_millis(500)).await;

    Ok(())
}
