# fleetos-agent

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

High-privilege Node Agent running on every FleetOS Worker Node.

`fleetos-agent` is the local representative of the control plane on each
worker node. It is the only thing standing between a workload and the
network on that node. It attests to `fleetos-control` to obtain its node
SVID, attests the MicroVMs it hosts, loads and populates eBPF maps that
enforce policy in the kernel, fetches secrets on demand, wraps overlay
traffic in QUIC, manages the workload lifecycle, and exports observability.

## Position in FleetOS

| Crate | Role |
|---|---|
| `fleetos-core` | Pure primitives: identity, hashing, attestation traits, policy schema, protos, crypto. Zero I/O. |
| `fleetos-ebpf` | Kernel enforcement plane: shared `#[repr(C)]` structs + Aya eBPF programs. |
| `fleetos-control` | The "brain": sole CA, sole scheduler, sole policy authority. |
| **`fleetos-agent`** | **This crate** — worker-node daemon. |
| `fleetos-router` | Data-plane transit nodes. |
| `fleetos-gateway` | Ingress/egress edge. |
| `fleetctl-proxy` | Admin API gateway, JIT access broker. |
| `fleetctl` | CLI (like `kubectl`). |

## Building

```bash
cargo build
```
## Running
```bash
fleetos-agent --config agent.toml
```

## eBPF Object

The agent expects the compiled eBPF object at the path specified in
`ebpf.object_path` (default: `/usr/lib/fleetos/fleetos-ebpf`).
Build the eBPF object from the fleetos-ebpf workspace:

```bash
cd ../fleetos-ebpf
cargo +nightly build --release --target bpfel-unknown-none -p fleetos-ebpf -Z build-std=core
```

The compiled object will be at:
`target/bpfel-unknown-none/release/fleetos-ebpf`

## Configuration
See `agent.example.toml` for a reference configuration.

## Dependencies

This crate depends on `fleetos-core` and `fleetos-ebpf-common` only.
It never depends on `fleetos-control` — it consumes control's gRPC
surface and trusts nothing else.

## License

Licensed under the Apache License, Version 2.0. You may obtain a copy of the License in the [LICENSE](LICENSE) file.
