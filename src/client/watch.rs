// SPDX-License-Identifier: Apache-2.0
//! Reconnecting watch streams for fleetos-control.
//!
//! Subscribes to WatchSag, WatchSchedule, WatchEvents, and WatchRoutes.
//! Tracks `last_known_version` to discard stale frames (Ruling B: every
//! frame is full state, so monotonicity is sufficient).
use crate::client::ControlPlaneClient;
use crate::client::retry::{BASE_RETRY_DELAY_MS, MAX_RETRY_DELAY_MS, RetryAction, classify_error};
use crate::error::AgentError;
use async_stream::stream;
use fleetos_core::proto::fleetos::{
    RouteUpdate, SagUpdate, ScheduleUpdate, WatchEvent, WatchRequest,
    policy_service_client::PolicyServiceClient,
    router_assignment_service_client::RouterAssignmentServiceClient,
    scheduler_service_client::SchedulerServiceClient, watch_service_client::WatchServiceClient,
};
use futures::Stream;
use std::sync::Arc;
use std::time::Duration;

pub fn watch_sag(
    control_client: Arc<ControlPlaneClient>,
) -> impl Stream<Item = Result<SagUpdate, AgentError>> {
    stream! {
        let mut last_known_version = 0u64;
        let mut redirect_hops = 0usize;
        let mut consecutive_failures = 0usize;

        loop {
            let channel = match control_client.get_channel().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to get channel for watch_sag");
                    yield Err(e);
                    tokio::time::sleep(Duration::from_millis(BASE_RETRY_DELAY_MS)).await;
                    continue;
                }
            };
            let mut client = PolicyServiceClient::new(channel);
            let req = WatchRequest {
                last_known_version,
            };

            match client.watch_sag(req).await {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    consecutive_failures = 0;
                    redirect_hops = 0;
                    loop {
                        match stream.message().await {
                            Ok(Some(update)) => {
                                if update.version > last_known_version {
                                    last_known_version = update.version;
                                    yield Ok(update);
                                }
                            }
                            Ok(None) => {
                                tracing::info!("watch_sag stream closed by server, reconnecting...");
                                break;
                            }
                            Err(status) => {
                                tracing::warn!(status = %status, "watch_sag stream error");
                                match classify_error(&status, redirect_hops) {
                                    RetryAction::RedirectAndRetry { new_target, delay } => {
                                        redirect_hops += 1;
                                        control_client.retarget(new_target).await;
                                        tokio::time::sleep(delay).await;
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        }
                    }
                }
                Err(status) => {
                    match classify_error(&status, redirect_hops) {
                        RetryAction::RedirectAndRetry { new_target, delay } => {
                            redirect_hops += 1;
                            control_client.retarget(new_target).await;
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::RetrySameTarget { delay } => {
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::GiveUp(reason) => {
                            consecutive_failures += 1;
                            let backoff_ms = (BASE_RETRY_DELAY_MS * 2u64.pow(consecutive_failures as u32)).min(MAX_RETRY_DELAY_MS);
                            tracing::error!(
                                reason = %reason,
                                backoff_ms = backoff_ms,
                                "watch_sag failed to connect, backing off"
                            );
                            yield Err(AgentError::Rpc(format!(
                                "watch connection failed: {}",
                                reason
                            )));
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }
        }
    }
}

pub fn watch_schedule(
    control_client: Arc<ControlPlaneClient>,
) -> impl Stream<Item = Result<ScheduleUpdate, AgentError>> {
    stream! {
        let mut last_known_version = 0u64;
        let mut redirect_hops = 0usize;
        let mut consecutive_failures = 0usize;

        loop {
            let channel = match control_client.get_channel().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to get channel for watch_schedule");
                    yield Err(e);
                    tokio::time::sleep(Duration::from_millis(BASE_RETRY_DELAY_MS)).await;
                    continue;
                }
            };
            let mut client = SchedulerServiceClient::new(channel);
            let req = WatchRequest {
                last_known_version,
            };

            match client.watch_schedule(req).await {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    consecutive_failures = 0;
                    redirect_hops = 0;
                    loop {
                        match stream.message().await {
                            Ok(Some(update)) => {
                                if update.version > last_known_version {
                                    last_known_version = update.version;
                                    yield Ok(update);
                                }
                            }
                            Ok(None) => {
                                tracing::info!("watch_schedule stream closed by server, reconnecting...");
                                break;
                            }
                            Err(status) => {
                                tracing::warn!(status = %status, "watch_schedule stream error");
                                match classify_error(&status, redirect_hops) {
                                    RetryAction::RedirectAndRetry { new_target, delay } => {
                                        redirect_hops += 1;
                                        control_client.retarget(new_target).await;
                                        tokio::time::sleep(delay).await;
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        }
                    }
                }
                Err(status) => {
                    match classify_error(&status, redirect_hops) {
                        RetryAction::RedirectAndRetry { new_target, delay } => {
                            redirect_hops += 1;
                            control_client.retarget(new_target).await;
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::RetrySameTarget { delay } => {
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::GiveUp(reason) => {
                            consecutive_failures += 1;
                            let backoff_ms = (BASE_RETRY_DELAY_MS * 2u64.pow(consecutive_failures as u32)).min(MAX_RETRY_DELAY_MS);
                            tracing::error!(
                                reason = %reason,
                                backoff_ms = backoff_ms,
                                "watch_schedule failed to connect, backing off"
                            );
                            yield Err(AgentError::Rpc(format!(
                                "watch connection failed: {}",
                                reason
                            )));
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }
        }
    }
}

pub fn watch_routes(
    control_client: Arc<ControlPlaneClient>,
) -> impl Stream<Item = Result<RouteUpdate, AgentError>> {
    stream! {
        let mut last_known_version = 0u64;
        let mut redirect_hops = 0usize;
        let mut consecutive_failures = 0usize;

        loop {
            let channel = match control_client.get_channel().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to get channel for watch_routes");
                    yield Err(e);
                    tokio::time::sleep(Duration::from_millis(BASE_RETRY_DELAY_MS)).await;
                    continue;
                }
            };
            let mut client = RouterAssignmentServiceClient::new(channel);
            let req = WatchRequest {
                last_known_version,
            };

            match client.watch_routes(req).await {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    consecutive_failures = 0;
                    redirect_hops = 0;
                    loop {
                        match stream.message().await {
                            Ok(Some(update)) => {
                                if update.version > last_known_version {
                                    last_known_version = update.version;
                                    yield Ok(update);
                                }
                            }
                            Ok(None) => {
                                tracing::info!("watch_routes stream closed by server, reconnecting...");
                                break;
                            }
                            Err(status) => {
                                tracing::warn!(status = %status, "watch_routes stream error");
                                match classify_error(&status, redirect_hops) {
                                    RetryAction::RedirectAndRetry { new_target, delay } => {
                                        redirect_hops += 1;
                                        control_client.retarget(new_target).await;
                                        tokio::time::sleep(delay).await;
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        }
                    }
                }
                Err(status) => {
                    match classify_error(&status, redirect_hops) {
                        RetryAction::RedirectAndRetry { new_target, delay } => {
                            redirect_hops += 1;
                            control_client.retarget(new_target).await;
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::RetrySameTarget { delay } => {
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::GiveUp(reason) => {
                            consecutive_failures += 1;
                            let backoff_ms = (BASE_RETRY_DELAY_MS * 2u64.pow(consecutive_failures as u32)).min(MAX_RETRY_DELAY_MS);
                            tracing::error!(
                                reason = %reason,
                                backoff_ms = backoff_ms,
                                "watch_routes failed to connect, backing off"
                            );
                            yield Err(AgentError::Rpc(format!(
                                "watch connection failed: {}",
                                reason
                            )));
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }
        }
    }
}

pub fn watch_events(
    control_client: Arc<ControlPlaneClient>,
) -> impl Stream<Item = Result<WatchEvent, AgentError>> {
    stream! {
        let mut redirect_hops = 0usize;
        let mut consecutive_failures = 0usize;

        loop {
            let channel = match control_client.get_channel().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to get channel for watch_events");
                    yield Err(e);
                    tokio::time::sleep(Duration::from_millis(BASE_RETRY_DELAY_MS)).await;
                    continue;
                }
            };
            let mut client = WatchServiceClient::new(channel);
            // WatchEvent is unversioned
            let req = WatchRequest { last_known_version: 0 };

            match client.watch_events(req).await {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    consecutive_failures = 0;
                    redirect_hops = 0;
                    loop {
                        match stream.message().await {
                            Ok(Some(update)) => yield Ok(update),
                            Ok(None) => {
                                tracing::info!("watch_events stream closed by server, reconnecting...");
                                break;
                            }
                            Err(status) => {
                                tracing::warn!(status = %status, "watch_events stream error");
                                match classify_error(&status, redirect_hops) {
                                    RetryAction::RedirectAndRetry { new_target, delay } => {
                                        redirect_hops += 1;
                                        control_client.retarget(new_target).await;
                                        tokio::time::sleep(delay).await;
                                    }
                                    _ => {}
                                }
                                break;
                            }
                        }
                    }
                }
                Err(status) => {
                    match classify_error(&status, redirect_hops) {
                        RetryAction::RedirectAndRetry { new_target, delay } => {
                            redirect_hops += 1;
                            control_client.retarget(new_target).await;
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::RetrySameTarget { delay } => {
                            tokio::time::sleep(delay).await;
                        }
                        RetryAction::GiveUp(reason) => {
                            consecutive_failures += 1;
                            let backoff_ms = (BASE_RETRY_DELAY_MS * 2u64.pow(consecutive_failures as u32)).min(MAX_RETRY_DELAY_MS);
                            tracing::error!(
                                reason = %reason,
                                backoff_ms = backoff_ms,
                                "watch_events failed to connect, backing off"
                            );
                            yield Err(AgentError::Rpc(format!(
                                "watch connection failed: {}",
                                reason
                            )));
                            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                        }
                    }
                }
            }
        }
    }
}
