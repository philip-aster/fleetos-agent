// fleetos-agent/build.rs

use std::process::Command;

fn main() {
    // Re-run build.rs if eBPF source files change
    println!("cargo:rerun-if-changed=../fleetos-ebpf/ebpf/src");
    println!("cargo:rerun-if-changed=../fleetos-ebpf/fleetos-ebpf-common/src");

    println!("cargo:warning=Building eBPF bytecode via xtask (nightly)...");

    // Execute xtask using rustup / +nightly explicitly, clearing outer RUSTC env var
    let status = Command::new("cargo")
        .env_remove("RUSTC") // <-- CRITICAL: Prevents outer cargo from forcing stable rustc
        .args(&["+nightly", "run", "--package", "xtask"])
        .current_dir("../fleetos-ebpf")
        .status()
        .expect("Failed to execute eBPF xtask build pipeline");

    if !status.success() {
        panic!("eBPF build pipeline failed! Cannot compile fleetos-agent without eBPF bytecode.");
    }
}
