# System Components

Component inventory for the gitp2p **v7.0.0** workspace (**8 packages**: 7 libraries in `libs/` + `cli` at repo root).

## Package Catalog

| Package | Path | Responsibility |
|---------|------|----------------|
| `cli` | `cli/` | User-facing CLI (`clap`); feature-gated dispatch to libraries |
| `gitp2p-core` | `libs/gitp2p-core/` | Metadata models/KV, identity IDs, trust/signing, vault lifecycle |
| `gitp2p-content` | `libs/gitp2p-content/` | Bundles, portable vaults, lineage, manifests, CAS/dedup/delta/merkle |
| `gitp2p-sync` | `libs/gitp2p-sync/` | Peer replication, filesystem/LAN/QUIC sync, local/peer recovery |
| `gitp2p-federation` | `libs/gitp2p-federation/` | Domains, gateways, peering, discovery, mobility, mesh, routing, relay, topology, global recovery |
| `gitp2p-runtime` | `libs/gitp2p-runtime/` | v6 autonomous runtime: policies, decision engine, agents, health, explainability |
| `gitp2p-enterprise` | `libs/gitp2p-enterprise/` | v7 org/team/role, governance, audit, compliance, admin, org trust, visibility |
| `gitp2p-verify` | `libs/gitp2p-verify/` | Unified verification pipeline (feature-gated for federation/runtime records) |

## Module map (merged from prior crates)

### `gitp2p-core`

- `metadata/` — models, KV I/O, Git helpers, errors
- `identity/` — PeerID, VaultID, CheckpointID, DomainID, etc.
- `trust/` — Ed25519 identity, zones, policies, delegation, trust graph
- `vault/` — `App`, vault/repo/checkpoint lifecycle, retention

### `gitp2p-content`

- `bundle/`, `portable/`, `media/`, `lineage/`, `manifest/`, `reconciliation/`
- `content/cas`, `content/dedup`, `content/delta`, `content/merkle`

### `gitp2p-sync`

- `sync/` — replication, discovery, QUIC transport, sessions
- `recovery/` — doctor, local, peer, multi recovery

### `gitp2p-federation`

- `domain/`, `gateway/`, `peering/`, `discovery/`, `mobility/`, `mesh/`
- `routing/`, `relay/`, `topology/`, `global_recovery`

### `gitp2p-runtime`

- `policy/`, `decision/`, `agents/` (sync, replica, recovery, trust), `health/`, `explain/`, `automation`

### `gitp2p-enterprise`

- `org/`, `team/`, `role/`, `governance/`, `audit/`, `compliance/`, `admin/`, `org_trust/`, `visibility/`

## Cargo features (CLI)

| Feature | Enables |
|---------|---------|
| *(default)* | `federation` + `runtime` + `enterprise` (full v7) |
| `federation` | v5 domain/gateway/peering/discover/global sync |
| `runtime` | v6 policy, automation, health, explain, replica, recovery, replay |
| `enterprise` | v7 org/governance/audit/compliance |

Build minimal v1–v4: `cargo build -p cli --no-default-features`

## Dependency graph

```
cli → verify, enterprise?, runtime?, federation?, sync, content, core
gitp2p-verify → federation?, runtime?, sync, content, core
gitp2p-enterprise → runtime, core
gitp2p-runtime → federation, sync, core
gitp2p-federation → sync, content, core
gitp2p-sync → content, core
gitp2p-content → core
```

## Ownership boundaries

| Concern | Owner | Not owned by |
|---------|-------|------------|
| KV models | `gitp2p-core::metadata` | CLI |
| On-disk vault layout | `gitp2p-core::vault` | sync |
| Transport sessions | `gitp2p-sync::sync` | federation |
| Cross-domain records | `gitp2p-federation` | core |
| Autonomous ticks | `gitp2p-runtime` | CLI |
| Org/governance KV | `gitp2p-enterprise` | federation |
