use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // 1. Tell Cargo to re-run build.rs if any eBPF source files change
    println!("cargo:rerun-if-changed=../fleetos-ebpf/ebpf/src");
    println!("cargo:rerun-if-changed=../fleetos-ebpf/fleetos-ebpf-common/src");

    println!("cargo:warning=Building eBPF bytecode via xtask (nightly)...");

    // 2. Resolve cargo/rustup path reliably (supporting sudo / Fedora wheel user environments)
    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    let rustup_path = find_rustup_binary();

    let (cmd_program, mut cmd_args): (String, Vec<String>) = if let Some(path) = rustup_path {
        (
            path.to_string_lossy().to_string(),
            vec![
                "run".into(),
                "nightly".into(),
                "cargo".into(),
                "run".into(),
                "--package".into(),
                "xtask".into(),
            ],
        )
    } else {
        (
            cargo_bin,
            vec![
                "+nightly".into(),
                "run".into(),
                "--package".into(),
                "xtask".into(),
            ],
        )
    };

    // Forward --release flag if outer cargo build is running in release mode
    if env::var("PROFILE").unwrap_or_default() == "release" {
        cmd_args.push("--".into());
        cmd_args.push("--release".into());
    }

    // 3. Execute xtask with host Rustc flags cleared to prevent cross-compilation leaks to eBPF target
    let mut cmd = Command::new(&cmd_program);
    cmd.env_remove("RUSTC")
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .args(&cmd_args)
        .current_dir("../fleetos-ebpf");

    let status = cmd.status().unwrap_or_else(|e| {
        panic!("Failed to launch eBPF build tool ({cmd_program}): {e}");
    });

    if !status.success() {
        panic!("eBPF build pipeline failed! Cannot compile fleetos-agent without eBPF bytecode.");
    }
}

/// Locates rustup binary, checking $HOME as well as $SUDO_USER home if executed with elevated privileges
fn find_rustup_binary() -> Option<PathBuf> {
    // Check standard $HOME/.cargo/bin/rustup
    if let Ok(home) = env::var("HOME") {
        let p = PathBuf::from(home).join(".cargo/bin/rustup");
        if p.exists() {
            return Some(p);
        }
    }

    // Fallback: Check sudo user home directory if running via sudo
    if let Ok(sudo_user) = env::var("SUDO_USER") {
        let p = PathBuf::from(format!("/home/{sudo_user}/.cargo/bin/rustup"));
        if p.exists() {
            return Some(p);
        }
    }

    None
}
