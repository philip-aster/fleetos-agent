use std::process::Command;

fn main() {
    // 1. Tell Cargo to re-run build.rs if any file in fleetos-ebpf changes
    println!("cargo:rerun-if-changed=../fleetos-ebpf/ebpf/src");
    println!("cargo:rerun-if-changed=../fleetos-ebpf/fleetos-ebpf-common/src");

    println!("cargo:warning=Building eBPF bytecode via xtask (nightly)...");

    // 2. Execute xtask using rustup / +nightly explicitly
    let status = Command::new("cargo")
        .args(&["+nightly", "run", "--package", "xtask"])
        .current_dir("../fleetos-ebpf")
        .status()
        .expect("Failed to execute eBPF xtask build pipeline");

    if !status.success() {
        panic!("eBPF build pipeline failed! Cannot compile fleetos-agent without eBPF bytecode.");
    }
}
