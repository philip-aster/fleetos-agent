// SPDX-License-Identifier: Apache-2.0
//! Probe state machine: liveness, readiness, startup probes.
//!
//! Startup probe gates liveness and readiness: until startup succeeds,
//! liveness and readiness are not evaluated.

pub mod exec;
pub mod http;
pub mod tcp;

use std::time::{Duration, Instant};

use fleetos_core::proto::workload::{Probe, ProbeSet};

/// Probe kind.
#[derive(Debug, Clone)]
pub enum ProbeKind {
    Exec { command: Vec<String> },
    HttpGet { path: String, port: u32 },
    TcpSocket { port: u32 },
}

impl From<&Probe> for ProbeKind {
    fn from(probe: &Probe) -> Self {
        if let Some(check) = &probe.check {
            match check {
                fleetos_core::proto::fleetos::probe::Check::Exec(exec) => ProbeKind::Exec {
                    command: exec.command.clone(),
                },
                fleetos_core::proto::fleetos::probe::Check::HttpGet(http) => ProbeKind::HttpGet {
                    path: http.path.clone(),
                    port: http.port,
                },
                fleetos_core::proto::fleetos::probe::Check::TcpSocket(tcp) => {
                    ProbeKind::TcpSocket { port: tcp.port }
                }
            }
        } else {
            ProbeKind::TcpSocket { port: 0 }
        }
    }
}

/// Probe phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbePhase {
    /// Waiting for initial delay.
    InitialDelay,
    /// Probing in progress.
    Probing,
    /// Probe succeeded.
    Succeeded,
    /// Probe failed.
    Failed,
}

/// Probe state machine.
pub struct ProbeRunner {
    kind: ProbeKind,
    phase: ProbePhase,
    initial_delay_secs: u32,
    period_secs: u32,
    timeout_secs: u32,
    success_threshold: u32,
    failure_threshold: u32,
    consecutive_successes: u32,
    consecutive_failures: u32,
    started_at: Instant,
    last_probe_at: Option<Instant>,
}

impl ProbeRunner {
    /// Create a new probe runner from a proto Probe.
    pub fn new(probe: &Probe) -> Self {
        Self {
            kind: ProbeKind::from(probe),
            phase: ProbePhase::InitialDelay,
            initial_delay_secs: probe.initial_delay_seconds,
            period_secs: probe.period_seconds,
            timeout_secs: probe.timeout_seconds,
            success_threshold: probe.success_threshold.max(1),
            failure_threshold: probe.failure_threshold.max(1),
            consecutive_successes: 0,
            consecutive_failures: 0,
            started_at: Instant::now(),
            last_probe_at: None,
        }
    }

    /// Whether it's time to run the next probe.
    pub fn is_due(&self) -> bool {
        let elapsed = self.started_at.elapsed();
        if elapsed < Duration::from_secs(self.initial_delay_secs as u64) {
            return false;
        }

        match self.last_probe_at {
            None => true,
            Some(last) => last.elapsed() >= Duration::from_secs(self.period_secs as u64),
        }
    }

    /// Run the probe and return the new phase.
    pub fn probe(&mut self) -> ProbePhase {
        self.last_probe_at = Some(Instant::now());
        self.phase = ProbePhase::Probing;

        let timeout = Duration::from_secs(self.timeout_secs as u64);
        let result = match &self.kind {
            ProbeKind::Exec { command } => exec::run_probe(command, timeout),
            ProbeKind::HttpGet { path, port } => http::run_probe(path, *port, timeout),
            ProbeKind::TcpSocket { port } => tcp::run_probe(*port, timeout),
        };

        match result {
            Ok(()) => {
                self.consecutive_successes += 1;
                self.consecutive_failures = 0;
                if self.consecutive_successes >= self.success_threshold {
                    self.phase = ProbePhase::Succeeded;
                } else {
                    self.phase = ProbePhase::Probing;
                }
            }
            Err(_) => {
                self.consecutive_failures += 1;
                self.consecutive_successes = 0;
                if self.consecutive_failures >= self.failure_threshold {
                    self.phase = ProbePhase::Failed;
                } else {
                    self.phase = ProbePhase::Probing;
                }
            }
        }

        self.phase
    }

    /// Whether the probe is currently passing.
    pub fn is_passing(&self) -> bool {
        self.phase == ProbePhase::Succeeded
    }

    /// Whether the probe is currently failing.
    pub fn is_failing(&self) -> bool {
        self.phase == ProbePhase::Failed
    }

    /// Get the current phase.
    pub fn phase(&self) -> ProbePhase {
        self.phase
    }
}

/// Probe set runner: manages startup, liveness, and readiness probes.
pub struct ProbeSetRunner {
    startup: Option<ProbeRunner>,
    liveness: Option<ProbeRunner>,
    readiness: Option<ProbeRunner>,
}

impl ProbeSetRunner {
    /// Create from a proto ProbeSet.
    pub fn new(probes: Option<&ProbeSet>) -> Self {
        let probes = probes.unwrap();
        Self {
            startup: probes.startup.as_ref().map(ProbeRunner::new),
            liveness: probes.liveness.as_ref().map(ProbeRunner::new),
            readiness: probes.readiness.as_ref().map(ProbeRunner::new),
        }
    }

    /// Whether startup probe has completed.
    pub fn startup_done(&self) -> bool {
        match &self.startup {
            None => true,
            Some(runner) => runner.is_passing(),
        }
    }

    /// Run all due probes. Returns (liveness_passing, readiness_passing).
    ///
    /// Startup probe gates liveness and readiness.
    pub fn run_probes(&mut self) -> (bool, bool) {
        // Run startup probe first.
        if let Some(startup) = &mut self.startup {
            if startup.is_due() {
                startup.probe();
            }
        }

        // If startup not done, liveness and readiness report passing.
        if !self.startup_done() {
            return (true, true);
        }

        // Run liveness probe.
        let liveness_passing = match &mut self.liveness {
            Some(runner) => {
                if runner.is_due() {
                    runner.probe();
                }
                runner.is_passing()
            }
            None => true,
        };

        // Run readiness probe.
        let readiness_passing = match &mut self.readiness {
            Some(runner) => {
                if runner.is_due() {
                    runner.probe();
                }
                runner.is_passing()
            }
            None => true,
        };

        (liveness_passing, readiness_passing)
    }

    /// Whether all probes are passing.
    pub fn all_passing(&self) -> bool {
        let startup_ok = self.startup_done();
        let liveness_ok = self
            .liveness
            .as_ref()
            .map(|r| r.is_passing())
            .unwrap_or(true);
        let readiness_ok = self
            .readiness
            .as_ref()
            .map(|r| r.is_passing())
            .unwrap_or(true);
        startup_ok && liveness_ok && readiness_ok
    }
}
