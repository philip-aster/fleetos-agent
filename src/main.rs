// SPDX-License-Identifier: Apache-2.0
//! fleetos-agent entrypoint.
//!
//! Batch 1: skeleton. Loads config, prints identity, exits cleanly.
//! Full wiring lands in Batch 12.

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "fleetos-agent", about = "FleetOS Node Agent")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "agent.toml")]
    config: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // Load config first (structural validation only).
    let config = match fleetos_agent::config::AgentConfig::load(&cli.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config {}: {}", cli.config.display(), e);
            return Err(e.into());
        }
    };

    // Initialize tracing subscriber.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // R-1 fence: insecure join mode must be loudly warned.
    if config.join.mode == fleetos_agent::config::JoinMode::Insecure {
        tracing::warn!("====================================================================");
        if cfg!(feature = "production") {
            tracing::warn!(
                "INSECURE JOIN MODE ENABLED IN A PRODUCTION BUILD via \
                 join.mode = \"insecure\"."
            );
            tracing::warn!(
                "RESIDUAL RISK: join-token possession alone grants cluster \
                 admission. Testing only; never a real deployment."
            );
        } else {
            tracing::warn!(
                "INSECURE JOIN MODE ACTIVE: join-token possession is the only \
                 gate to cluster admission and quote signatures are NOT verified. \
                 TESTING ONLY — never use in a real deployment."
            );
        }
        tracing::warn!("====================================================================");
    }

    tracing::info!(
        config = %cli.config.display(),
        node = %config.node.name,
        trust_domain = %config.node.trust_domain,
        control = %config.control.address,
        "fleetos-agent configuration loaded"
    );

    // Batch 1: skeleton only. Print and exit.
    tracing::info!("fleetos-agent skeleton initialized successfully");

    Ok(())
}
