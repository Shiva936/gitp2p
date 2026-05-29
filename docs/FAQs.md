# Frequently Asked Questions

## General Questions

### What is gitp2p?

A local-first CLI for protected Git vaults, signed recovery checkpoints, trusted peer sync, and decentralized global federation (v5). It is not a Git hosting service.

### How is gitp2p different from Git?

Git tracks source history. gitp2p adds vaults, signed checkpoints, trust policies, peer sync, and cross-domain federation on top of Git.

### How is gitp2p different from GitHub?

GitHub is centralized hosting. gitp2p runs on your machine with optional peer-to-peer sync—no account or remote required.

### Who is gitp2p for?

Developers and teams who want sovereign recovery, airgapped workflows, trusted LAN collaboration, or cross-organizational sync without mandatory cloud infrastructure.

## Installation Questions

### Does gitp2p work on WSL?

Yes. Use Linux paths for repos and set `GITP2P_PEER_HOMES` to cross-mount peer homes (e.g. `/mnt/c/Users/...`).

### Why does `cargo build` take long?

The workspace has 27 crates including QUIC/TLS dependencies. Build only the CLI: `cargo build -p gitp2p-cli`.

### Can I install without building from source?

There is no official prebuilt release pipeline documented yet. Build from source with Cargo.

## Usage Questions

### What is the difference between checkpoint and sync?

**Checkpoint** captures a signed recovery point locally. **Sync** replicates mirror state to a trusted peer (or across a federation path).

### Do I need to trust a peer before syncing?

Yes. Discover with `peers discover`, then `trust approve <peer-id>`.

### What are trust zones?

Labels like `trusted`, `readonly`, `quarantined` that control export, sync push, and checkpoint behavior per repo. See [HOW_IT_WORKS.md](HOW_IT_WORKS.md).

### How does global federation work (v5)?

Create domains and gateways, peer domains, optionally delegate trust, then `sync --domain <remote>`. Discovery aggregates from local and gateway caches—no central registry.

### What is the difference between mesh and global sync?

**Mesh** routes through trusted peer hops locally. **Global sync** builds a cross-domain route with gateway hops and records the path in `sync inspect`.

## Performance Questions

### How many concurrent syncs can run?

Default limit is 2 (`GITP2P_MAX_CONCURRENT_SYNCS`). Raise cautiously.

### Does gitp2p deduplicate storage?

Yes, via CAS (`gitp2p-cas`) and dedup stats. Mirrors still store full Git history per vault.

### Will federation scale to thousands of domains?

v5 uses KV file scans for discovery caches. Large deployments should plan for future wire protocol and indexing improvements.

## Security Questions

### Where is my private key stored?

In `~/.gitp2p/identity` as a KV file. Protect with filesystem permissions.

### What does quarantined zone do?

Denies all repo actions including sync and export until the zone is changed.

### How do I verify a checkpoint?

`gitp2p checkpoint verify <checkpoint-id>`

### How do I verify federation records (v5)?

```bash
gitp2p verify domain <domain-id>
gitp2p verify gateway <gateway-id>
gitp2p verify peering <remote-domain>
gitp2p verify delegation <delegation-id>
gitp2p verify route <route-id>
```

## Contribution Questions

### How do I run tests?

```bash
cargo test
```

Integration tests use temp directories and Git repos; no network required.

### Where do I add a new feature?

Prefer extending existing crates per [architecture/EXTENSIBILITY.md](architecture/EXTENSIBILITY.md). New federation features go in the v5 crates.

See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Troubleshooting Questions

### Error: peer is not known

Run `gitp2p peers discover` (with `--lan` or `GITP2P_PEER_HOMES`), then `trust approve`.

### Error: relay is disabled

Run `gitp2p relay enable` before global sync.

### Error: no local gateway found

Create a gateway before peering: `gitp2p gateway create --domain <domain>`.

### Error: domain/gateway not found

List with `gitp2p domain inspect` or `gitp2p gateway inspect`.

### Recovery finds no sources

Run `gitp2p recover sources <repo>` to list candidates. Ensure peers are trusted and checkpoints exist remotely.

### repo doctor reports unhealthy

Use `recover` from last good checkpoint or trusted peer.

---

**Maintenance rule:** Update this file when the same question appears repeatedly.

**Related documents:** [GETTING_STARTED.md](GETTING_STARTED.md) · [HOW_IT_WORKS.md](HOW_IT_WORKS.md) · [SECURITY.md](SECURITY.md)
