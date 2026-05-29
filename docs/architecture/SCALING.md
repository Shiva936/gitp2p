# Scaling

Scaling characteristics and limits of gitp2p v5.0.0.

## Bottlenecks

| Bottleneck | Cause |
|------------|-------|
| Filesystem I/O | Full Git mirror copy per sync |
| Single-home writer | No concurrent multi-process writes |
| Peer fan-out | Each sync is pairwise |
| Gateway hop latency | Sequential relay forward audit |
| KV scan | Listing large peer/route caches |
| Concurrent sync cap | Default 2 parallel sessions |

## Horizontal Scaling

gitp2p scales **out** by adding nodes, not by sharding one vault:

- More peers → mesh routing finds paths.
- More domains → gateway peering mesh (decentralized discovery cache).
- More replicas → `discover replicas` / `recover sources` ranking.

There is no built-in load balancer; operators choose peers/domains explicitly or via `auto` recovery.

## Vertical Scaling

- Faster disk → faster mirror sync and CAS operations.
- More RAM → marginal benefit (streaming design).
- More CPU → Git operations and crypto signing scale linearly.

## Resource Consumption

| Resource | Typical use |
|----------|-------------|
| Disk | O(repo history × vaults) + CAS chunks |
| Network | Proportional to mirror delta (bundle/delta aware) |
| CPU | Git + Ed25519 sign/verify |
| File descriptors | Low except QUIC listener |

## Capacity Planning

| Dimension | Practical guidance |
|-----------|-------------------|
| Repos per vault | Limited by disk; no hard cap |
| Peers | Hundreds of KV records feasible; discovery scans grow O(n) |
| Checkpoints | Use retention prune to bound metadata |
| Domains | Federation metadata lightweight; gateway exchange grows with peering |
| Concurrent syncs | Raise `GITP2P_MAX_CONCURRENT_SYNCS` cautiously |

For enterprise-scale monorepos, prefer incremental bundles (`--since`) and CAS dedup.

---

**Related documents:** [NETWORKING.md](NETWORKING.md) · [DEPLOYMENT_ARCHITECTURE.md](DEPLOYMENT_ARCHITECTURE.md) · [FAILURE_RECOVERY.md](FAILURE_RECOVERY.md)
