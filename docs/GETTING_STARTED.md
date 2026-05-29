# Getting Started

Complete onboarding guide for gitp2p v5.0.0.

## Prerequisites

- **Rust** — Stable toolchain with `cargo` ([rustup.rs](https://rustup.rs))
- **Git** — For repository operations
- **OS** — Linux, macOS, or WSL2
- **Disk space** — Enough for Git mirror copies of registered repos

Optional for LAN sync: multicast DNS support on your network.

## Installation

Clone the repository and build the CLI:

```bash
git clone <repository-url> gitp2p
cd gitp2p
cargo build -p gitp2p-cli
```

The binary is at `target/debug/gitp2p`. Add it to your `PATH` or use `cargo run -p gitp2p-cli --`.

Verify the build:

```bash
cargo test
```

## Initial Configuration

### Home directory

By default gitp2p stores state in `~/.gitp2p`. Override with:

```bash
export GITP2P_HOME=/path/to/your/home
```

### Identity

On first run gitp2p creates an Ed25519 identity:

```bash
gitp2p identity show
```

Expected output includes `peer_id`, `fingerprint`, and `public_key`.

Export for backup:

```bash
gitp2p id export ./my-identity.backup
```

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GITP2P_HOME` | `~/.gitp2p` | State root |
| `GITP2P_PEER_HOMES` | — | Comma-separated peer home paths |
| `GITP2P_TRANSPORT` | `auto` | `filesystem`, `quic`, or `auto` |
| `GITP2P_LISTEN_PORT` | `9134` | QUIC/mDNS port |
| `GITP2P_MAX_CONCURRENT_SYNCS` | `2` | Parallel sync limit |
| `GITP2P_BUNDLE_KEY` | — | Bundle encryption key |

See [DEPLOYMENT_ARCHITECTURE.md](architecture/DEPLOYMENT_ARCHITECTURE.md) for multi-domain setups.

## First Run

From a Git repository directory:

```bash
# 1. Create a vault
gitp2p vault create myteam

# 2. Register the current repo
gitp2p repo add myteam .

# 3. Create a recovery checkpoint
gitp2p checkpoint

# 4. Recover to a new directory (validation)
gitp2p recover repo --target ./recovered-copy --auto-recover
```

Expected: checkpoint ID printed, recovery completes with mirror at target path.

## Verification

```bash
gitp2p repo doctor repo          # Git integrity check
gitp2p checkpoint verify <cp-id> # Signature check
gitp2p identity show             # Confirm identity exists
```

## Workflow Examples

### Trusted peer sync (v2)

Filesystem transport for shared mounts, NAS, or WSL:

```bash
GITP2P_PEER_HOMES=/path/to/peer-b/.gitp2p gitp2p peers discover
gitp2p peers discover --lan --timeout 5
gitp2p trust approve <peer-id>
gitp2p sync my-repo --peer <peer-id>
gitp2p peers listen   # mDNS + QUIC receiver
```

### Offline bundles (v3)

```bash
gitp2p bundle create my-repo --structured
gitp2p bundle validate ./bundle.bundle
gitp2p vault export myteam --output ./myteam.vaultpkg
gitp2p recover my-repo --offline ./bundle.bundle
gitp2p lineage inspect <checkpoint-id>
```

### Mesh federation (v4)

```bash
gitp2p route inspect --destination <peer-id>
gitp2p relay enable
gitp2p topology summary
gitp2p recover my-repo --network <peer-id>
```

### Identity and verification (v4.5)

```bash
gitp2p id inspect
gitp2p peers verify <peer-id>
gitp2p checkpoint verify <checkpoint-id>
gitp2p manifest verify ./manifest.json
gitp2p lineage verify <checkpoint-id> <hash>
```

### Global federation (v5)

```bash
gitp2p domain create local
gitp2p gateway create --domain local
gitp2p peer-domain connect <remote-domain> --gateway <gateway-id>
gitp2p trust delegate <target> --type domain --scope sync
gitp2p discover domains
gitp2p route inspect --global --destination <remote-domain>
gitp2p relay enable
gitp2p sync my-repo --domain <remote-domain>
gitp2p sync inspect
gitp2p recover global my-repo --domain <remote-domain>
gitp2p verify domain <domain-id>
```

## Common Issues

| Issue | Solution |
|-------|----------|
| `peer '...' is not known` | Run `peers discover`, then `trust approve` |
| `relay is disabled` | Run `gitp2p relay enable` before global sync |
| `no local gateway found` | Create gateway before peering: `gateway create` |
| Permission denied on `GITP2P_HOME` | Fix directory permissions or choose writable path |
| WSL path not found | Use `/mnt/c/...` paths or set `GITP2P_PEER_HOMES` explicitly |
| Build fails on QUIC | Ensure OpenSSL/ring deps; try `cargo build -p gitp2p-cli` only |

## Next Steps

- [HOW_IT_WORKS.md](HOW_IT_WORKS.md) — Conceptual overview
- [architecture/OVERVIEW.md](architecture/OVERVIEW.md) — Architecture map
- [SECURITY.md](SECURITY.md) — Security policies
- [FAQs.md](FAQs.md) — Common questions
- [CONTRIBUTING.md](../CONTRIBUTING.md) — Contribute to the project

---

**Related documents:** [README.md](../README.md) · [HOW_IT_WORKS.md](HOW_IT_WORKS.md) · [architecture/GLOSSARY.md](architecture/GLOSSARY.md)
