// SPDX-License-Identifier: Apache-2.0
//! Tests for the redirect-and-retry classification logic.

use fleetos_agent::client::retry::{
    LEADER_DC_ADDRESS_KEY, MAX_REDIRECT_HOPS, RetryAction, classify_error,
};
use std::time::Duration;
use tonic::{Code, Status};

fn make_status(code: Code, msg: &str) -> Status {
    Status::new(code, msg)
}

fn make_status_with_leader(code: Code, msg: &str, leader: &str) -> Status {
    let mut status = Status::new(code, msg);
    status
        .metadata_mut()
        .insert(LEADER_DC_ADDRESS_KEY, leader.parse().unwrap());
    status
}

#[test]
fn unavailable_without_leader_retries_same_target() {
    let status = make_status(Code::Unavailable, "node is down");
    let action = classify_error(&status, 0);
    match action {
        RetryAction::RetrySameTarget { delay } => {
            assert!(delay.as_millis() > 0);
        }
        other => panic!("expected RetrySameTarget, got {:?}", other),
    }
}

#[test]
fn unavailable_with_leader_redirects() {
    let status = make_status_with_leader(Code::Unavailable, "not leader", "10.0.0.5:9443");
    let action = classify_error(&status, 0);
    match action {
        RetryAction::RedirectAndRetry { new_target, delay } => {
            assert_eq!(new_target, "10.0.0.5:9443");
            assert_eq!(delay, Duration::from_millis(0));
        }
        other => panic!("expected RedirectAndRetry, got {:?}", other),
    }
}

#[test]
fn permission_denied_gives_up() {
    let status = make_status(Code::PermissionDenied, "no SVID");
    let action = classify_error(&status, 0);
    assert!(matches!(action, RetryAction::GiveUp(_)));
}

#[test]
fn not_found_gives_up() {
    let status = make_status(Code::NotFound, "secret missing");
    let action = classify_error(&status, 0);
    assert!(matches!(action, RetryAction::GiveUp(_)));
}

#[test]
fn max_hops_exceeded_gives_up() {
    let status = make_status_with_leader(Code::Unavailable, "not leader", "10.0.0.5:9443");
    let action = classify_error(&status, MAX_REDIRECT_HOPS + 1);
    assert!(matches!(action, RetryAction::GiveUp(_)));
}

#[test]
fn empty_leader_address_falls_back_to_retry() {
    let status = make_status_with_leader(Code::Unavailable, "not leader", "   ");
    let action = classify_error(&status, 0);
    assert!(matches!(action, RetryAction::RetrySameTarget { .. }));
}

#[test]
fn backoff_increases_with_hops() {
    let status = make_status(Code::Unavailable, "transient");
    let action0 = classify_error(&status, 0);
    let action1 = classify_error(&status, 1);
    let action2 = classify_error(&status, 2);

    let d0 = match action0 {
        RetryAction::RetrySameTarget { delay } => delay,
        _ => panic!(),
    };
    let d1 = match action1 {
        RetryAction::RetrySameTarget { delay } => delay,
        _ => panic!(),
    };
    let d2 = match action2 {
        RetryAction::RetrySameTarget { delay } => delay,
        _ => panic!(),
    };

    assert!(d1 > d0);
    assert!(d2 > d1);
}
