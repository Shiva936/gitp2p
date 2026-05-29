# Storage Architecture

Persistence layout and consistency model for gitp2p.

## Storage Systems

gitp2p uses the local filesystem exclusively. There is no embedded database.

| Store | Location | Format |
|-------|----------|--------|
| Identity | `~/.gitp2p/identity` | KV (peer_id, keys, fingerprint) |
| Vaults | `~/.gitp2p/vaults/<vault-id>/` | Directories + KV metadata |
| Peers | `~/.gitp2p/peers/<peer-id>` | KV |
| Sessions | `~/.gitp2p/sessions/` | KV |
| CAS | `~/.gitp2p/cas/` | Content-addressed files |
| Routing | `~/.gitp2p/routing/` | KV (local + `global/`) |
| Relay | `~/.gitp2p/relay/` | KV state + forward cache |
| Federation | `~/.gitp2p/federation/` | KV domains, gateway dirs, peering, delegations |
| Discovery | `~/.gitp2p/discovery/` | KV cache per kind |
| Sync paths | `~/.gitp2p/sync/paths/` | KV global sync audit |
| TLS | `~/.gitp2p/tls/` | Generated certs for QUIC |

Override root with `GITP2P_HOME`.

## Data Organization

```text
~/.gitp2p/
├── identity
├── tls/
├── cas/
├── routing/
│   ├── route-<destination>          # local routes
│   └── global/<route-id>            # cross-domain routes
├── relay/
│   ├── state
│   └── cache/
├── federation/
│   ├── domains/<domain-id>
│   ├── gateways/<gateway-id>/
│   │   ├── gateway                  # gateway record
│   │   └── exchange/                # route/discovery manifests
│   ├── peering/<peering-id>
│   └── delegations/<delegation-id>
├── discovery/
│   ├── domains/
│   ├── gateways/
│   ├── vaults/
│   └── replicas/
├── sync/paths/<session-id>
├── vaults/<vault-id>/
│   ├── metadata/
│   │   ├── vault
│   │   ├── repos/<repo-id>
│   │   └── checkpoints/<cp-id>
│   ├── repositories/<repo-id>/      # Git mirror
│   └── replication/<peer-repo>
├── peers/<peer-id>
├── sessions/<session-id>
├── trust-graph/
└── trust-requests/
```

Each vault mirror is a bare Git repository managed by gitp2p; working trees remain at the user's registered path.

## Consistency Model

- **Single-writer per home** — One gitp2p process should write to a given `GITP2P_HOME` at a time.
- **KV atomic writes** — `write_kv_atomic` used for critical records where implemented.
- **Signed records** — Domains, gateways, peerings, delegations, checkpoints, and sessions carry signatures for offline verification.
- **Eventual cross-domain consistency** — Gateway exchange caches propagate route/discovery metadata asynchronously (filesystem simulation in v5).

## Backup Strategy

- Copy entire `GITP2P_HOME` for full backup.
- Export vaults with `gitp2p vault export` for portable packages.
- Export bundles with `gitp2p bundle create` for repo-level offline backup.
- Identity backup: copy `identity` file or use `gitp2p id export`.

## Recovery Strategy

- **Local:** Latest checkpoint in vault metadata.
- **Peer:** Trusted peer mirror via `gitp2p recover --peer`.
- **Offline:** Bundle import via `gitp2p recover --offline`.
- **Global:** Cross-domain replica discovery via `gitp2p recover global` / `recover sources`.

See [FAILURE_RECOVERY.md](FAILURE_RECOVERY.md).

## Retention Policies

Vault and repo policies control checkpoint pruning:

- `gitp2p vault policy set` / repo-level overrides
- `gitp2p checkpoint prune --keep N --older-than SECS`
- Retention enforced optionally at checkpoint creation (`--enforce-retention`)

---

**Related documents:** [OVERVIEW.md](OVERVIEW.md) · [FAILURE_RECOVERY.md](FAILURE_RECOVERY.md) · [DATA_FLOW.md](DATA_FLOW.md)
