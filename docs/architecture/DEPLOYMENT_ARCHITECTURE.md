# Deployment Architecture

How gitp2p is deployed and configured in practice.

## Supported Deployments

| Deployment | Description |
|------------|-------------|
| **Single developer** | One machine, default `~/.gitp2p`, local vaults |
| **WSL + Windows share** | `GITP2P_PEER_HOMES` pointing across WSL/Windows paths |
| **NAS / shared mount** | Filesystem peer discovery across mounted homes |
| **Airgapped** | Bundles and vault packages; no network |
| **Multi-domain simulation** | Separate `GITP2P_HOME` per domain for federation testing |
| **LAN collaborators** | mDNS + optional QUIC listener |

There is no server package, container image, or cloud control plane in-tree.

## Infrastructure Requirements

- **OS:** Linux, macOS, or WSL2
- **Rust:** Stable toolchain (2021 edition)
- **Git:** Required for repository operations
- **Disk:** Space for vault mirrors (full Git history per repo)
- **Network (optional):** UDP for mDNS/QUIC; multicast for LAN discovery

## Runtime Dependencies

Built from source:

```bash
cargo build -p gitp2p-cli
# binary: target/debug/gitp2p
```

Workspace version: **5.0.0** (27 crates, resolver v2).

## Environment Layouts

| Variable | Default | Purpose |
|----------|---------|---------|
| `GITP2P_HOME` | `~/.gitp2p` | State root |
| `GITP2P_PEER_HOMES` | — | Comma-separated peer home paths for filesystem discovery |
| `GITP2P_TRANSPORT` | `auto` | `filesystem`, `quic`, or `auto` |
| `GITP2P_LISTEN_PORT` | `9134` | QUIC/mDNS listen port |
| `GITP2P_MAX_CONCURRENT_SYNCS` | `2` | Parallel sync limit |
| `GITP2P_BUNDLE_KEY` | — | Bundle encryption key material |

### Multi-domain federation layout

For cross-domain testing, use isolated homes:

```bash
GITP2P_HOME=/tmp/domain-a-home gitp2p domain create domain-a
GITP2P_HOME=/tmp/domain-b-home gitp2p domain create domain-b
```

Peering and gateway exchange connect domains via KV manifests (filesystem simulation).

## Upgrade Strategy

1. Pull latest source.
2. `cargo build -p gitp2p-cli`
3. Existing `GITP2P_HOME` is forward-compatible; new v5 dirs created on first federation command.
4. Run `cargo test` before production use on critical vaults.
5. Bump workspace version in root `Cargo.toml` for releases.

Backup `GITP2P_HOME` before major version upgrades.

---

**Related documents:** [GETTING_STARTED.md](../GETTING_STARTED.md) · [STORAGE.md](STORAGE.md) · [EXECUTION_MODEL.md](EXECUTION_MODEL.md)
