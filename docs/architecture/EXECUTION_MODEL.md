# Execution Model

Runtime behavior of the gitp2p CLI and subsystem crates.

## Runtime Lifecycle

1. **Startup** — `App::load()` resolves `GITP2P_HOME`, `ensure_home()` creates base dirs, `ensure_identity()` loads or generates Ed25519 identity.
2. **Command dispatch** — `clap` parses argv; `main.rs` matches subcommands; extended handlers in `extended.rs` for v3–v5 features.
3. **Operation** — Subsystem crate performs work (vault, sync, federation, verify).
4. **Persistence** — KV records written under home; sessions updated through phases.
5. **Exit** — Success prints summary; errors print `error: ...` and exit code 1.

No long-running daemon by default except `peers listen` (mDNS + QUIC server).

## Scheduling

- **Synchronous CLI** — Most commands block until completion.
- **Async LAN/QUIC** — `gitp2p-sync` uses tokio runtime (`current_thread`) for mDNS browse and QUIC accept loops.
- **Concurrent sync cap** — `GITP2P_MAX_CONCURRENT_SYNCS` limits parallel sessions.

## Concurrency Model

- Single-process CLI; no internal thread pool for vault operations.
- Tokio used only for network discovery/server paths.
- Filesystem is the coordination layer; avoid concurrent writers to same `GITP2P_HOME`.

## Event Processing

| Event | Handler |
|-------|---------|
| Peer discovered | `write_peer`, optional trust request |
| Sync started | Session KV created, phase `negotiate` |
| Transfer progress | Session `transfer_artifact`, offset tracking |
| Relay forward | Cache entry in `relay/cache/` |
| Gateway exchange | Manifest written to `gateways/<id>/exchange/` |
| Checkpoint created | Signed KV + repo `latest_checkpoint` update |

## State Transitions

### Session phases

```text
negotiate → transfer → complete
```

Failed sessions remain in sessions dir for inspection via `sync status`.

### Peering states

```text
active → revoked
```

Revoked peerings fail route verification.

### Delegation states

```text
active → revoked
```

Revoked delegations break delegation chain validation.

## Resource Management

- **Memory** — Streaming Git operations; bundles may be large on disk not in RAM.
- **Disk** — Vault mirrors duplicate repo history; CAS dedup reduces redundant chunks.
- **Network** — QUIC listen port default 9134 (`GITP2P_LISTEN_PORT`).
- **File handles** — KV read/write per operation; no persistent connection pool.

---

**Related documents:** [DATA_FLOW.md](DATA_FLOW.md) · [SYSTEM_COMPONENTS.md](SYSTEM_COMPONENTS.md) · [DEPLOYMENT_ARCHITECTURE.md](DEPLOYMENT_ARCHITECTURE.md)
