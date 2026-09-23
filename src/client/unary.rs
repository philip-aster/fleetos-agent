// SPDX-License-Identifier: Apache-2.0
//! Unary RPC wrappers for fleetos-control.
//!
//! These wrap the generated tonic clients with our redirect-and-retry
//! logic and SVID-stamping where required.
use crate::client::ControlPlaneClient;
use crate::client::retry::{RetryAction, classify_error};
use crate::error::AgentError;
use fleetos_core::proto::fleetos::{
    CsrRequest, DelegatedKeyRequest, DelegatedKeyResponse, FetchSecretRequest, MetricsAck,
    PodEvent, PodMetrics, ReportPodEventsRequest, SealedSecret, StatusAck, SvidResponse,
    TrustBundle, TrustBundleRequest, WorkloadStatusReport, ca_service_client::CaServiceClient,
    delegation_service_client::DelegationServiceClient,
    pod_event_service_client::PodEventServiceClient, secret_service_client::SecretServiceClient,
    workload_status_service_client::WorkloadStatusServiceClient,
};

const MAX_TRANSIENT_RETRIES: usize = 3;

pub async fn fetch_secret(
    control_client: &ControlPlaneClient,
    target_spiffe_id: &str,
    svid_version: u64,
) -> Result<SealedSecret, AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = SecretServiceClient::new(channel);
        let req = FetchSecretRequest {
            target_spiffe_id: target_spiffe_id.to_string(),
            sealed_for_svid_version: svid_version,
        };

        match client.fetch_secret(req).await {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    tracing::info!(leader = %new_target, "FetchSecret redirect, retargeting");
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "FetchSecret failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!("FetchSecret failed: {}", reason)));
                }
            },
        }
    }
}

pub async fn report_workload_status(
    control_client: &ControlPlaneClient,
    report: WorkloadStatusReport,
) -> Result<StatusAck, AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = WorkloadStatusServiceClient::new(channel);
        let req = report.clone();

        match client.report_workload_status(req).await {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "ReportWorkloadStatus failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!(
                        "ReportWorkloadStatus failed: {}",
                        reason
                    )));
                }
            },
        }
    }
}

pub async fn report_pod_metrics(
    control_client: &ControlPlaneClient,
    metrics: PodMetrics,
) -> Result<MetricsAck, AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = WorkloadStatusServiceClient::new(channel);
        let req = metrics.clone();

        match client.report_pod_metrics(req).await {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "ReportPodMetrics failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!(
                        "ReportPodMetrics failed: {}",
                        reason
                    )));
                }
            },
        }
    }
}

pub async fn report_pod_events(
    control_client: &ControlPlaneClient,
    events: Vec<PodEvent>,
) -> Result<(), AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = PodEventServiceClient::new(channel);
        let req = ReportPodEventsRequest {
            events: events.clone(),
        };

        match client.report_pod_events(req).await {
            Ok(_) => return Ok(()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "ReportPodEvents failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!(
                        "ReportPodEvents failed: {}",
                        reason
                    )));
                }
            },
        }
    }
}

pub async fn request_delegated_key(
    control_client: &ControlPlaneClient,
    request: DelegatedKeyRequest,
) -> Result<DelegatedKeyResponse, AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = DelegationServiceClient::new(channel);
        let req = request.clone();

        match client.request_delegated_key(req).await {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "RequestDelegatedKey failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!(
                        "RequestDelegatedKey failed: {}",
                        reason
                    )));
                }
            },
        }
    }
}

pub async fn submit_csr(
    control_client: &ControlPlaneClient,
    csr_der: Vec<u8>,
) -> Result<SvidResponse, AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = CaServiceClient::new(channel);
        let req = CsrRequest {
            csr_der: csr_der.clone(),
        };

        match client.submit_csr(req).await {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "SubmitCsr failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!("SubmitCsr failed: {}", reason)));
                }
            },
        }
    }
}

pub async fn get_trust_bundle(
    control_client: &ControlPlaneClient,
) -> Result<TrustBundle, AgentError> {
    let mut redirect_hops = 0usize;
    let mut transient_retries = 0usize;

    loop {
        let channel = control_client.get_channel().await?;
        let mut client = CaServiceClient::new(channel);
        let req = TrustBundleRequest {};

        match client.get_trust_bundle(req).await {
            Ok(response) => return Ok(response.into_inner()),
            Err(status) => match classify_error(&status, redirect_hops) {
                RetryAction::RedirectAndRetry { new_target, .. } => {
                    redirect_hops += 1;
                    control_client.retarget(new_target).await;
                }
                RetryAction::RetrySameTarget { delay } => {
                    transient_retries += 1;
                    if transient_retries > MAX_TRANSIENT_RETRIES {
                        return Err(AgentError::Rpc(format!(
                            "GetTrustBundle failed after {} retries: {}",
                            transient_retries,
                            status.message()
                        )));
                    }
                    tokio::time::sleep(delay).await;
                }
                RetryAction::GiveUp(reason) => {
                    return Err(AgentError::Rpc(format!(
                        "GetTrustBundle failed: {}",
                        reason
                    )));
                }
            },
        }
    }
}
