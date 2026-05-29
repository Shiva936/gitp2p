# Failure and Recovery

Resilience mechanisms across local, peer, and federation scopes.

## Failure Classes

| Class | Example | Detection |
|-------|---------|-----------|
| **Repository corruption** | Broken Git mirror | `gitp2p repo doctor` |
| **Missing checkpoint** | Deleted metadata | `checkpoint list` empty |
| **Peer unavailable** | Offline remote | Sync error |
| **Trust failure** | Revoked peer | Authorization deny |
| **Gateway failure** | Unreachable gateway | Route verify / failover |
| **Domain outage** | Remote domain down | Global discovery empty |
| **Delegation revoked** | Chain break | `verify delegation` fails |

## Recovery Strategies

| Strategy | Command | Scope |
|----------|---------|-------|
| Local checkpoint | `recover <repo> --auto-recover` | Same machine |
| Specific checkpoint | `recover <repo> --checkpoint <id>` | Same machine |
| Peer recovery | `recover <repo> --peer <id>` | Trusted peer |
| Best peer auto | `recover <repo> --peer auto` | Multi-peer selection |
| Offline bundle | `recover <repo> --offline <bundle>` | Airgap |
| Network/mesh | `recover <repo> --network <peer>` | Multi-hop |
| Global recovery | `recover global <repo> --domain <id>` | Cross-domain |
| Source listing | `recover sources <repo>` | Compare replicas |

Recovery validates checkpoint signatures and Git integrity (`git fsck`) before restore.

## Checkpointing

- Created with `gitp2p checkpoint` or as part of sync.
- Signed by local identity; verifiable with `checkpoint verify`.
- Lineage chain inspectable via `lineage inspect`.
- Prunable per retention policy.

Checkpoints are the primary rollback point—not Git reflog alone.

## Rollback

- Restore to earlier checkpoint via `recover --checkpoint`.
- Prune newer checkpoints after successful recovery if policy allows.
- Quarantined repos cannot export/sync until zone changed.

## Disaster Recovery

1. **Identity loss** — Restore from `id export` backup; peer IDs must match for trust graph.
2. **Full home loss** — Restore `GITP2P_HOME` backup or re-import vault packages/bundles.
3. **Regional/domain loss** — `recover global` discovers replicas in peered domains.
4. **Gateway path failure** — `failover_route` builds alternate gateway ordering.

## Data Integrity Guarantees

- Ed25519 signatures on checkpoints, sessions, federation records.
- Merkle root verification for lineage leaves.
- CAS chunk verify via `verify` pipeline.
- Manifest hash verification for bundles.
- Doctor runs `git fsck` on mirrors.

Integrity is **verify-on-use**; background scanning is operator-triggered.

---

**Related documents:** [DATA_FLOW.md](DATA_FLOW.md) · [STORAGE.md](STORAGE.md) · [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md)
