// fleetos-agent/build.rs

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // 1. Tell Cargo to re-run build.rs if any eBPF source files change
    println!("cargo:rerun-if-changed=../fleetos-ebpf/ebpf/src");
    println!("cargo:rerun-if-changed=../fleetos-ebpf/fleetos-ebpf-common/src");

    println!("cargo:warning=Building eBPF bytecode via xtask (nightly)...");

    // 2. Resolve cargo/rustup path reliably (checking cargo home for sudo/Fedora environments)
    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());

    // Find rustup or fallback to cargo
    let home = env::var("HOME").unwrap_or_default();
    let user_rustup = PathBuf::from(home).join(".cargo/bin/rustup");

    let (cmd_program, cmd_args): (String, Vec<&str>) = if user_rustup.exists() {
        (
            user_rustup.to_string_lossy().to_string(),
            vec!["run", "nightly", "cargo", "run", "--package", "xtask"],
        )
    } else {
        (cargo_bin, vec!["+nightly", "run", "--package", "xtask"])
    };

    // 3. Execute xtask with RUSTC removed to prevent outer cargo env lock
    let status = Command::new(&cmd_program)
        .env_remove("RUSTC")
        .args(&cmd_args)
        .current_dir("../fleetos-ebpf")
        .status()
        .unwrap_or_else(|e| {
            panic!("Failed to launch eBPF build tool ({cmd_program}): {e}");
        });

    if !status.success() {
        panic!("eBPF build pipeline failed! Cannot compile fleetos-agent without eBPF bytecode.");
    }
}
