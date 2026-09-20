## Revised Directory Tree

```
fleetos-agent/
├── Cargo.toml                        # Batch 1 — deps pinned to core v0.2.0-rc-5 / ebpf v0.1.3-rc-3
├── agent.example.toml                # Batch 1 — reference config, secure-mode defaults
├── README.md                         # Batch 1 — build/run notes, object-path expectation (AA-8)
├── fleetos-agent-ledger.md           # Living document — rulings A–G, audit findings, upstream blockers
│
├── src/
│   ├── main.rs                       # Batch 1 skeleton → Batch 12 full wiring
│   ├── lib.rs                        # Batch 1 — module surface (tests import via lib)
│   ├── error.rs                      # Batch 1 — AgentError, incl. PendingUpstream (fail-closed)
│   ├── config.rs                     # Batch 1 — TOML config + validation + insecure-mode fence
│   ├── storage.rs                    # Batch 2 — fjall db + agent keyspaces
│   │
│   ├── identity/
│   │   ├── mod.rs                    # Batch 2
│   │   ├── svid.rs                   # Batch 2 — SvidState: installed SVID + LIVE version (S-10) + generation counter
│   │   ├── sequences.rs              # Batch 2 — SecretSequenceTracker: per-(target, svid_version) replay guard
│   │   ├── keystore.rs               # Batch 2 — TPM-sealed storage for X25519 privkey + delegated keys (Ruling G)
│   │   └── degraded.rs               # Batch 8 — DelegatedSigningKey lifecycle: 4h TTL, refresh @75%
│   │
│   ├── join/
│   │   ├── mod.rs                    # Batch 9
│   │   ├── secure.rs                 # Batch 9 — CR-10 credential activation (RequestActivation → ActivateCredential → Quote → SubmitActivationProof)
│   │   └── insecure.rs               # Batch 9 — join-token flow, fenced TESTING ONLY (mirrors control's R-1)
│   │
│   ├── client/
│   │   ├── mod.rs                    # Batch 3 — ControlPlaneClient: current-target state, leader bookkeeping
│   │   ├── channels.rs               # Batch 3 — TLS channel building: ServerTrust (join) + Mtls (post-SVID), cert-generation tracking
│   │   ├── retry.rs                  # Batch 3 — THE shared redirect-and-retry helper (O-1, mandatory)
│   │   ├── watch.rs                  # Batch 3 — reconnecting subscriptions: SAG / Schedule / Events / Routes, last-version tracking
│   │   └── unary.rs                  # Batch 3 — FetchSecret, ReportWorkloadStatus, RequestDelegatedKey, SubmitCsr, GetTrustBundle, ReportPodMetrics, ReportPodEvents
│   │
│   ├── ebpf/
│   │   ├── mod.rs                    # Batch 4 — EbpfManager: owns the loaded object + attach lifecycle
│   │   ├── loader.rs                 # Batch 4 — Aya load: pre-load map sizing (Ruling C) + pin lifecycle (AA-3)
│   │   ├── maps.rs                   # Batch 4 — typed map ops: POLICY_EXACT/WILDCARD, DUMMY_IP_ROUTE_MAP, SRC_IDENTITY_MAP, LOCAL_WORKLOADS, BOOT_GATE
│   │   ├── programs.rs               # Batch 4 — attach: connect4 + sockops (cgroup, node-wide), TC egress/ingress (per-iface, BOOT-RACE)
│   │   ├── events.rs                 # Batch 4 — FLOW_EVENTS ringbuf drain → FlowEvent
│   │   └── counters.rs              # Batch 4 — POD_NET_COUNTERS PerCpuHashMap reader: sum across CPUs, diff with wrapping_sub (EBPF-CR-5)
│   │
│   ├── policy/
│   │   ├── mod.rs                    # Batch 5 — SagCompiler trait boundary + CompiledPolicyEntry
│   │   ├── stub.rs                   # Batch 5 — CompilerNotYetAvailable → PendingUpstream (Ruling A blocker)
│   │   └── sync.rs                   # Batch 5 — full-state policy sync: desired-set diff, stale sweep, reload-on-exhaustion trigger
│   │
│   ├── routes/
│   │   ├── mod.rs                    # Batch 6
│   │   ├── table.rs                  # Batch 6 — RouteUpdate → DUMMY_IP_ROUTE_MAP + LOCAL_WORKLOADS (own-node filter)
│   │   └── hosts.rs                  # Batch 6 — /etc/hosts injection builder (Ruling E, v1 static)
│   │
│   ├── vsock_attest/                # Batch 7 — CR-CORE-6 agent leg (renamed from guest/, expanded)
│   │   ├── mod.rs                    # VsockAttestServer: accept loop on HOST_CID:0x4649, drives 4-step handshake
│   │   ├── verify.rs                 # QuoteVerifier impl: nonce binding, quote_type dispatch, fail-closed gates
│   │   ├── measure.rs                # Host-measured boot: BLAKE3(kernel + erofs + guest-init) pre-launch measurement
│   │   └── config_push.rs            # WorkloadConfig construction + push after attestation passes
│   │
│   ├── secrets/
│   │   ├── mod.rs                    # Batch 8
│   │   ├── fetch.rs                  # Batch 8 — FetchSecret: leader-bound, stamps live svid_version (S-10)
│   │   └── deliver.rs                # Batch 8 — proto SealedSecret → core SealedSecret → unseal; replay check; workload delivery (TODO)
│   │
│   ├── workloads/                    # Batch 10 — lifecycle phase; stubs with hard guard-rails
│   │   ├── mod.rs                    # Reconcile entry point from WatchSchedule assignments
│   │   ├── reconciler.rs             # FULL-STATE reconcile: desired assignments vs running pods
│   │   ├── pod_manager.rs            # PodSpec → runtime spec; pod state machine (Pending→Running→Terminating…)
│   │   ├── lifecycle.rs              # termination: SIGTERM → grace wait → force; RestartPolicy + backoff
│   │   ├── probes/
│   │   │   ├── mod.rs                # probe state machine: initial_delay, period, timeout, thresholds, startup gating
│   │   │   ├── exec.rs
│   │   │   ├── http.rs
│   │   │   └── tcp.rs
│   │   ├── volumes/
│   │   │   └── mod.rs                # STUBBED — blocked on G2 (volume source schema)
│   │   ├── env.rs                    # env injection + /etc/hosts lines (Ruling E)
│   │   ├── containerd.rs             # containerd pod lifecycle (stub)
│   │   ├── microvm.rs                # cloud-hypervisor boot + VmNetGuard (boot-race, Rule #7)
│   │   └── status.rs                 # Batch 11 — WorkloadStatusReport builder; policy_enforced TODO(Ruling D)
│   │
│   └── observability/
│       ├── flow_events.rs            # Batch 11 — FlowEvent → OTLP push structure (no inbound scrape, ever)
│       └── pod_events.rs             # Batch 11 — Pod lifecycle events → PodEventService.ReportPodEvents (CR-CORE-8)
│
└── tests/
    ├── redirect_retry.rs             # Batch 3 — retry policy classification (pure, no server)
    ├── sequence_replay.rs            # Batch 2 — replay protection semantics
    ├── dummy_ip_keying.rs            # Batch 6 — canonical IPv4 value → HostOrderIpv4 (CR-3 byte-order path)
    ├── policy_sync.rs                # Batch 5 — desired-state diff logic
    ├── sealed_secret_conv.rs         # Batch 8 — proto↔core conversion round-trip
    ├── counters_rate.rs              # Batch 4 — POD_NET_COUNTERS aggregate + rate logic (pure, no eBPF)
    └── vsock_handshake.rs            # Batch 7 — VSOCK wire protocol round-trip via frame_msg/decode_msg
```

### Constraints that shaped this tree (unchanged + new)

- **Dependency direction is one-way.** We depend on `fleetos-core` and `fleetos-ebpf-common` only. Never on `fleetos-control`.
- **`lib.rs` + thin `main.rs`** so integration tests can import modules without launching the daemon.
- **No inbound listeners** except the VSOCK attestation server (`vsock_attest/`, port `0x4649`) and the user-space rewrite target (`127.0.0.1:4242`), both local-only.
- **Fail-closed stubs.** Anything blocked upstream returns `PendingUpstream` — never "empty policy = allow".
- **`proxy/` deferred.** No current justification. If the user-space rewrite target needs its own module later, we'll add it then.
- **`vsock_attest/` replaces `guest/`.** The name was ambiguous (confusable with `fleetos-guest-init`). The new name makes the direction unambiguous: this is the host-side verifier.
- **`ebpf/counters.rs` is a reader, not a writer.** The kernel owns the increments; the agent owns the read-sum-diff-report pipeline.

---

## Revised Execution Plan

Delivery model unchanged: **one batch per message from me**, complete file contents. You implement locally, run the gate, relay errors. We resolve before the next batch.

### Batch 1 — Skeleton (compiles, does nothing)

| File | Purpose |
|---|---|
| `Cargo.toml` | Deps: `fleetos-core` (features: `production`), `fleetos-ebpf-common`, `fleetos-policy-compiler` (Ruling A resolved), `aya 0.14.x`, `tonic 0.14.x`, `tokio`, `fjall`, `postcard`, `tss-esapi`, `zeroize`, `blake3`, etc. Added `dev` feature gated by `fleetos_dev` cfg. |
| `lib.rs` / `main.rs` | Module declarations; `main` prints config path and exits cleanly. |
| `error.rs` | `AgentError` incl. `PendingUpstream(&'static str)`. |
| `config.rs` | `AgentConfig`: node, control addr, join (mode/token/bundle path/PCR indices), tpm backend, storage path, ebpf (object path, cgroup, pin path, headroom), svid refresh, vsock attest (listen addr, boot-artifact paths). Validation + loud insecure-mode warning. |
| `agent.example.toml`, `README.md` | Reference config; build/run + eBPF object expectation. |

- **Rulings touched:** none yet — scaffolding.
- **Gate:** `cargo check`. No tests yet.

### Batch 2 — Identity state & storage

| File | Purpose |
|---|---|
| `storage.rs` | fjall db open + agent keyspaces: `svid`, `secret_state`, `delegation`, `sequences`. |
| `identity/svid.rs` | `SvidState`: hot-swappable installed SVID, **live `svid_version` (S-10)**, generation counter (channels rebuild on rotation). |
| `identity/sequences.rs` | `SecretSequenceTracker`: strictly-newer-or-reject per `(target, svid_version)`. Fail-closed. |
| `identity/keystore.rs` | Trait `SensitiveStore` + `TpmSealedStore` (TPM2_Seal under an SRK; PCR-binding flagged as follow-up). X25519 private key + delegated keys **never in plaintext in fjall** — Ruling G non-negotiable. |
| `tests/sequence_replay.rs` | Replay semantics. |

- **Rulings touched:** G (storage + keystore), S-10 (version tracking).
- **Gate:** `cargo test`.

### Batch 3 — Control client (the redirect-and-retry foundation)

| File | Purpose |
|---|---|
| `client/channels.rs` | Channel construction: server-trust TLS (pre-SVID join leg) and mTLS (post-SVID). Rebuild when SVID generation bumps. |
| `client/retry.rs` | **The** shared redirect-and-retry helper: on `UNAVAILABLE` + `leader-dc-address` metadata → retarget and retry, capped (5 hops). Pure classification function extracted for testability. |
| `client/mod.rs` | `ControlPlaneClient`: current target, leader bookkeeping, mode switching. |
| `client/watch.rs` | Reconnecting subscriptions for `WatchSag` / `WatchSchedule` / `WatchEvents` / `WatchRoutes` with `last_known_version` tracking; every frame is full state (Ruling B), discard via version monotonicity. |
| `client/unary.rs` | `FetchSecret` (leader-bound), `ReportWorkloadStatus`, `ReportPodMetrics`, `ReportPodEvents`, `RequestDelegatedKey`, `SubmitCsr`, `GetTrustBundle`, attestation RPCs. |
| `tests/redirect_retry.rs` | Retry classification without a live server. |

- **Rulings touched:** O-1 (mandatory helper), B (full-state frames), AA-1 (client types imported from `fleetos_core::proto::fleetos::<svc>_client` until core exports them).
- **Gate:** `cargo test`.

### Batch 4 — eBPF loader lifecycle + counters reader

| File | Purpose |
|---|---|
| `ebpf/loader.rs` | Aya `EbpfLoader`: **pre-load map sizing from initial state + headroom (Ruling C)**, pin-path management and stale-pin removal (AA-3), controlled-reload trigger on map exhaustion. |
| `ebpf/maps.rs` | Typed map ops. `LOCAL_WORKLOADS` mirrored as `HashMap<IdentityFingerprint, u8>` (AA-7). `BOOT_GATE` arming. |
| `ebpf/programs.rs` | Attach `fleetos_connect4` + `fleetos_sockops` at cgroup (node-wide, once); TC egress/ingress per interface — **synchronous/blocking before guest network-up (boot-race, Rule #7)** via a `VmNetGuard` type. |
| `ebpf/events.rs` | `FLOW_EVENTS` ringbuf drain → `FlowEvent` structs. |
| `ebpf/counters.rs` | **NEW (EBPF-CR-5).** `PodNetCountersReader`: reads `POD_NET_COUNTERS` as `PerCpuHashMap<HostOrderIpv4, PodNetCounters>`, sums across all possible CPUs, stores previous aggregate, computes per-second rates via `wrapping_sub`. Pure computation extracted for testability. |
| `ebpf/mod.rs` | `EbpfManager` owning it all. |
| `tests/counters_rate.rs` | **NEW.** Aggregate + rate logic over synthetic `PodNetCounters` arrays. Covers: sum across CPUs, zero-interval → `None`, no-change → zero rates, wraparound via `wrapping_sub`. Mirrors the reference implementation locked in `fleetos-ebpf-common/tests/pod_net_counters_contract.rs`. |

- **Rulings touched:** C, AA-2 (SOCKHASH fast path NOT wired), AA-3, AA-7, AA-8, EBPF-CR-5.
- **Gate:** `cargo check` + `cargo test` (map-key byte-order helpers + counters rate logic). Full attach test is a **manual privileged pass on a dev node**.

### Batch 5 — Policy boundary (stubbed until Ruling A lands)

| File | Purpose |
|---|---|
| `policy/mod.rs` | `SagCompiler` trait + `CompiledPolicyEntry` enum (Exact/Wildcard). |
| `policy/stub.rs` | `CompilerNotYetAvailable` → `PendingUpstream("fleetos-policy-compiler (Ruling A)")`. Node stays default-deny meanwhile. |
| `policy/sync.rs` | Full-state sync: compute desired key set from compiled entries, diff against tracked keys, insert new / delete absent, stamp `sag_version`. |
| `tests/policy_sync.rs` | Diff logic over plain key sets (no eBPF needed). |

- **Gate:** `cargo test`. When the compiler carve-out lands, only `stub.rs` gets swapped.

### Batch 6 — Routes & name resolution

| File | Purpose |
|---|---|
| `routes/table.rs` | `RouteUpdate` → `DUMMY_IP_ROUTE_MAP` entries (`dst_fp`, `target_agent_fp` via `IdentityFingerprint::of` — Rule #1, never `of_with_ordinal`), `LOCAL_WORKLOADS` set for destinations hosted on this node, `SRC_IDENTITY_MAP` registration hooks. |
| `routes/hosts.rs` | `/etc/hosts` line builder for containerd OCI-spec mount and guest-init handoff (Ruling E, v1 static). Uses `fleetos_core::naming::dummy_ip_hostname`. |
| `tests/dummy_ip_keying.rs` | CR-3 canonical-value → network-order → `HostOrderIpv4` round-trip. |

- **Rulings touched:** E, plus the fingerprint invariant.
- **Gate:** `cargo test`.

### Batch 7 — VSOCK attestation server (CR-CORE-6 agent leg) ← NEW

| File | Purpose |
|---|---|
| `vsock_attest/mod.rs` | `VsockAttestServer`: binds `HOST_CID=2` / port `0x4649`, accept loop, drives the strict 4-step handshake per `fleetos_core::vsock_proto`. Enforces 16 MiB cap. One listener per hosting agent. |
| `vsock_attest/verify.rs` | `QuoteVerifier` impl for the VSOCK channel. Dispatch by `quote_type`: `0xFF` (Dev) → reject fail-closed in production; `3` (Host-Measured) → verify CID matches launched VM + boot-artifact hash; `1/2` (SEV-SNP/TDX) → gate exists, fail-closed. Nonce binding enforced. `protocol_version != 1` → reject. |
| `vsock_attest/measure.rs` | Host-measured boot: BLAKE3 hash of kernel + erofs rootfs + `fleetos-guest-init` binary *before* launching Cloud Hypervisor. Stores measurement for CID-bound verification. |
| `vsock_attest/config_push.rs` | `WorkloadConfig` construction: SVID cert chain + private key (agent-generated keypair), env vars, volume mounts, dummy-IP routes (from `routes/table.rs`), workload binary path, trust domain, tenant/service/role, guest networking. Pushed after attestation passes. |
| `tests/vsock_handshake.rs` | Wire protocol round-trip via `frame_msg`/`decode_msg` for all four message types. Locks the postcard layout from the agent side (mirrors `fleetos-guest-init/src/protocol.rs` tests). |

- **Rulings touched:** CR-CORE-6 (closes the Core Lead's blocker), D1 ruling (host-measured quote type), fail-closed gates.
- **Dependencies:** Batch 2 (SVID state), Batch 3 (client for trust bundles), Batch 6 (routes for `dummy_ip_routes` in `WorkloadConfig`).
- **Gate:** `cargo test`. Live VSOCK test requires a Cloud Hypervisor VM — manual pass.

### Batch 8 — Secrets & degraded mode

| File | Purpose |
|---|---|
| `secrets/fetch.rs` | `FetchSecret` via the retry helper; stamps **live `svid_version` (S-10)**; fails if no SVID installed. |
| `secrets/deliver.rs` | proto `SealedSecret` → core `SealedSecret` conversion, `unseal` with the TPM-recovered private key, sequence check, handoff point to workloads (TODO until Batch 10). |
| `identity/degraded.rs` | `DelegatedSigningKey` lifecycle: acquire via `RequestDelegatedKey`, 4h TTL, refresh at 75% while control reachable, local renewal via `sign_svid_delegated` when unreachable. |
| `tests/sealed_secret_conv.rs` | Conversion round-trip + replay rejection. |

- **Rulings touched:** S-10, O-1, degraded-mode invariants (onboarding §6).
- **Gate:** `cargo test`.

### Batch 9 — Join flows

| File | Purpose |
|---|---|
| `join/secure.rs` | CR-10: `AttestationSession::begin` → `RequestActivation` → `activate` → `compute_activation_proof` → `quote(server_nonce, pcr_indices)` → CSR via `build_csr` → `SubmitActivationProof` → install SVID + `GetTrustBundle`. Redirect-and-retry on leader redirects. |
| `join/insecure.rs` | Join-token flow with structural `TpmQuote` (postcard-encoded into `raw_quote`, AA-6), **fenced exactly like control's R-1**: compiled out of production builds; refuses at runtime otherwise. |

- **Note:** join is the runtime's *first* act but is built here because it stands on Batches 2–3.
- **Gate:** `cargo test` (structural). Optional live pass against swtpm.

### Batch 10 — Workload lifecycle stubs + boot-race guard

| File | Purpose |
|---|---|
| `workloads/mod.rs` | Reconcile entry point from `WatchSchedule` assignments. |
| `workloads/reconciler.rs` | FULL-STATE reconcile: desired assignments vs running pods. Present in frame + absent locally → boot. Absent in frame + present locally → graceful eviction. |
| `workloads/pod_manager.rs` | PodSpec → runtime spec; pod state machine. |
| `workloads/lifecycle.rs` | Termination: SIGTERM → grace wait → force; RestartPolicy + backoff. |
| `workloads/probes/` | Probe state machine: initial_delay, period, timeout, success/failure thresholds, startup gating liveness/readiness. `exec.rs`, `http.rs`, `tcp.rs`. |
| `workloads/volumes/mod.rs` | STUBBED — blocked on G2 (volume source schema). |
| `workloads/env.rs` | Env injection + `/etc/hosts` lines (Ruling E). |
| `workloads/containerd.rs` | Stub with the OCI-spec `/etc/hosts` mount hook defined. |
| `workloads/microvm.rs` | Stub with `VmNetGuard` contract: **TC attach + map population must complete before the TAP device comes up** — synchronous, no race. |
| `workloads/status.rs` | `WorkloadStatusReport` builder; `policy_enforced` TODO(Ruling D). |

- **Gate:** `cargo check` + design review. Real implementation is a later directive; the guard-rail shape is what we lock now.

### Batch 11 — Status reporting & observability

| File | Purpose |
|---|---|
| `workloads/status.rs` | Reporter loop. `policy_enforced` field is **TODO(Ruling D)** until the `state.proto` change lands; builder structured so it's a one-line wire later. `router_connected` (Directive A.1). `restart_count` + `started` (CR-CORE-3). |
| `observability/flow_events.rs` | Ringbuf drain loop → OTLP push (metrics/traces), outbound-only. |
| `observability/pod_events.rs` | **NEW (CR-CORE-8 / CR-CTRL-7).** Pod lifecycle event reporter: batches events, sends via `PodEventService.ReportPodEvents`. Canonical vocabulary: `Pulled`, `Created`, `Started`, `ProbeFailed`, `BackOff`, `OOMKilled`, `Evicting`, `GracePeriodExpired`, `FailedScheduling`, `Resizing`, `Resized`. |
| `ebpf/counters.rs` (reporting loop) | Periodic read → aggregate → rate → `ReportPodMetrics` via `client/unary.rs`. Merges TAP-path counters with containerd proxy accounting before reporting. |

- **Gate:** `cargo check`.

### Batch 12 — Full wiring & shutdown

| File | Purpose |
|---|---|
| `main.rs` | Complete runtime: config → storage → keystore → SVID load/join → client → eBPF → watch loops → vsock attest server → status/observability → counters reporting → graceful shutdown (drain streams → detach programs → flush fjall). |

- **Gate:** `cargo check`, `cargo test`, then a **manual smoke procedure** on a dev node: config loads, join fails cleanly without a control plane, eBPF object loads if present, VSOCK listener binds, clean shutdown.


---


# fleetos-agent — Living Ledger

## Rulings

### Ruling A — SAG compiler extraction (RESOLVED)
The SAG→eBPF compilation logic has been successfully extracted into the shared
`fleetos-policy-compiler` crate. The agent now depends on it directly.
Batch 5 will wire the real compiler instead of the `policy/stub.rs` fail-closed stub. 
When I require the source, I should ask the PM.

### Ruling B — Watch streams carry no initial-state frame
`WatchSag`/`WatchSchedule`/`WatchRoutes`/`WatchEvents` emit only on change,
nothing on subscribe. On agent restart in a quiet cluster the agent comes up
with empty policy/routes/schedule. Default-deny is fail-safe, but it's a
policy vacuum until the next mutation. Decision pending: initial full-state
frame on subscribe, or unary state-fetch RPC.

### Ruling C — Policy-map sizing
The handoff says maps are "sized generously by fleetos-agent at load time,"
but the current `fleetos-ebpf` source hardcodes sizes in `HashMap::pinned(...)`.
Confirm whether the agent is expected to resize/own these at load, and
reconcile with the source.

### Ruling D — Readiness gate
A pod does not transition to `Running` until (container/MicroVM started) AND
(`policy_enforced`) AND (router connectivity confirmed). The `policy_enforced`
field is TODO until the `state.proto` change lands (CR-CORE-3).

### Ruling E — Dummy-IP resolution mechanism
Options: local stub resolver, NSS module, or `/etc/hosts` injection.
Not yet decided. v1 uses `/etc/hosts` injection (static).

### Ruling F — `sock_ops` vs identity-header ordering
Whether `sock_ops` fires before or after the application-level identity
header is visible on a local connection. Determines the same-node fast-path
implementation. Unresolved.

### Ruling G — TPM-sealed storage for sensitive keys (CR-CORE-5)
The agent's X25519 sealing private key (and any delegated signing keys)
must never sit in plaintext in fjall. The key is generated pre-attestation
and must survive restarts. It must be persisted TPM-sealed (bound to the
node's PCR state). `fleetos_core::attestation::tpm::seal_to_pcr` /
`unseal` landed in core v0.2.0-rc-5.

## Audit Findings

### AA-1 — Missing client exports in core
Core's `proto.rs` exports server types for `PolicyService`, `SchedulerService`,
`WatchService`, and `SecretService`, but only exports clients for
`WorkloadStatusServiceClient` and `DelegationServiceClient`. The agent
additionally needs clients for `WatchSag`, `WatchSchedule`, `WatchEvents`,
and `FetchSecret`. Filed as CR-CORE-4.

### AA-2 — SockTuple key mismatch breaks same-node fast path
In `fleetos-ebpf/src/main.rs`, `fleetos_connect4` inserts `SOCK_STATE_MAP`
keyed with `src_port = HostOrderPort(0)` and the original dummy `dst_ip`,
while `fleetos_sockops` builds its lookup tuple from the post-rewrite
endpoints. These keys can never match, so `SOCKHASH` bypass never fires.
Fix belongs to the eBPF Lead. The agent's `LOCAL_WORKLOADS` design is
affected but not blocked.

### AA-3 — Pinned maps vs resize
The eBPF source hardcodes map sizes in `HashMap::pinned(...)`. If the agent
is expected to resize maps at load time (Ruling C), the pin lifecycle needs
reconciliation: stale-pin removal, controlled-reload trigger on map exhaustion.

### AA-4 — Core sealing primitive
`fleetos_core::attestation::tpm::seal_to_pcr` / `unseal` landed in
core v0.2.0-rc-5 (CR-CORE-5). PCR-binding policy is caller-supplied.
The agent must decide which PCRs to bind at seal time.

### AA-6 — Insecure join structural quote
The insecure join flow uses a structural `TpmQuote` (postcard-encoded into
`raw_quote`). The quote is never cryptographically verified. Fenced exactly
like control's R-1: compiled out of production builds; refuses at runtime
otherwise.

### AA-7 — LOCAL_WORKLOADS mirrored as HashMap
`LOCAL_WORKLOADS` is mirrored in userspace as `HashMap<IdentityFingerprint, u8>`
for fast lookup without a map probe. The kernel map is the source of truth;
the userspace mirror is a cache that must be kept in sync.

### AA-8 — eBPF object path expectation
The agent expects the compiled eBPF object at `ebpf.object_path`. The object
must be built from the `fleetos-ebpf` workspace with the exact toolchain
documented in its README. Version mismatch between the agent's expected ABI
and the object's actual ABI is a hard failure.

## Upstream Blockers

### G1 — WorkloadAssignment is too thin to boot a pod
`state.proto` streams only `workload_id, runtime, image, role`. Missing
`pod_id`, `ordinal`, resources, volumes, probes, env, ports, termination.
Filed as CR-CORE-1. Agent cannot implement Batch 10 correctly until this lands.

### G2 — Volume sources don't exist
`VolumeMount` without a `Volume` definition is a mount with nothing to mount.
Filed as CR-CORE-2. Agent's `workloads/volumes/` module is stubbed until
the schema lands.

### G3 — WorkloadStatusReport needs restart_count, started, policy_enforced
Filed as CR-CORE-3. Agent's `workloads/status.rs` builder is structured so
these fields are a one-line wire when the proto change lands.

### G4 — Drain semantics
`EvictNode` removes placements → full-state schedule frame omits them →
agent terminates gracefully. Coherent but undocumented. No `DrainNode` RPC,
no PDB equivalent.

### G6 — Pod lifecycle events
No pod-scoped event stream. Filed as CR-CORE-8 / CR-CTRL-7. Agent's
`observability/pod_events.rs` is stubbed until the proto lands.

### Question H — Readiness → routing coupling
In K8s, an unready pod is removed from endpoints. In FleetOS, who enforces
that? The dummy-IP route table is Raft-replicated from placements, not
readiness. Needs an architect ruling.

### Work Ledger Entries

| Work Item | Status |
| ---|---|
| Created Initial Scafolding: Initial scaffolding for the FleetOS Node Agent, revised directory structure. | Complete |
| Batch 1: Skeleton | Complete |
| Add `dev` feature with `fleetos_dev` cfg guard and `production` feature flag. | Complete |
| Update `Cargo.toml` to use `fleetos-core` `production` feature and link `fleetos-policy-compiler`. | Complete |
| Update `fleetos-agent-ledger.md` to mark Ruling A as RESOLVED. | Complete |
