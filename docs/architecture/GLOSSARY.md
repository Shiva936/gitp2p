# Glossary

Single source of truth for gitp2p terminology. See also [HOW_IT_WORKS.md](../HOW_IT_WORKS.md) for conceptual context.

## Core Concepts

**Checkpoint** — An immutable, signed snapshot of a repository at a specific Git commit. Checkpoints are the unit of recovery and replication.

**Identity** — The local cryptographic identity (Ed25519 key pair) that owns vaults, signs checkpoints, and derives the **Peer ID**.

**Lineage** — The ordered chain of checkpoints for a repository, used to verify history and propagation integrity.

**Peer** — Another gitp2p node discovered via filesystem, LAN, or federation. Peers have trust states (`trusted`, `readonly`, `revoked`, etc.).

**Repository (Repo)** — A Git working tree registered inside a vault. gitp2p tracks sync state, trust zone, and checkpoints per repo.

**Session** — A sync operation between local and remote peer, with phases (`negotiate`, `transfer`, `complete`) and optional signatures.

**Vault** — A sovereign container for one or more repositories, policies, checkpoints, and replication metadata.

## Internal Terms

**CAS (Content-Addressable Storage)** — Chunk store under `~/.gitp2p/cas/` keyed by content hash.

**Global route** — A cross-domain path stored under `routing/global/`, including gateway hop metadata.

**KV record** — Key-value metadata file used throughout gitp2p for domains, peers, sessions, and routes.

**Mesh sync** — Multi-hop synchronization through trusted peers using local routing.

**Sync path** — Record of a global sync traversal stored under `sync/paths/`.

## Architectural Terms

**Delegation** — Signed trust extension from one identity to a peer, domain, gateway, or federation scope.

**Discovery cache** — Decentralized aggregate of domains, gateways, vaults, and replicas under `discovery/`.

**Federation domain** — A sovereign trust/routing/peering boundary identified by a **Domain ID**.

**Gateway** — Domain boundary node that exchanges routes and discovery with peer domains.

**Global Sovereign Federation (v5)** — Independent domains connected via gateways without a mandatory central registry.

**Peering** — Signed, revocable relationship linking two domains through gateway endpoints.

**Trust zone** — Per-repository policy label (`trusted`, `readonly`, `protected`, `quarantined`, etc.) governing actions.

## User-Facing Terms

**Bundle** — Portable offline export/import package for repositories or structured federation data.

**Doctor** — Repository integrity check (`gitp2p repo doctor`).

**Recover** — Restore a repository from local checkpoint, peer, bundle, or cross-domain replica.

**Verify** — Cryptographic validation of peers, checkpoints, manifests, domains, gateways, peerings, delegations, or routes.

## Acronyms

| Acronym | Meaning |
|---------|---------|
| CAS | Content-addressable storage |
| CoC | Code of Conduct |
| FRD | Functional requirements document (internal release specs) |
| KV | Key-value (metadata file format) |
| LAN | Local area network (mDNS discovery) |
| mDNS | Multicast DNS (`_gitp2p._tcp.local.`) |
| QUIC | UDP-based transport used with TLS for peer sync |
| TLS | Transport Layer Security |
| WSL | Windows Subsystem for Linux |

## ID Prefixes

| Prefix | Entity | Example |
|--------|--------|---------|
| `domain-` | Federation domain | `domain-local` |
| `gw-` | Gateway | `gw-6df2e63a99548f4f` |
| `peer-` | Peering manifest | `peer-domain-a-domain-b` |
| `del-` | Trust delegation | `del-a1b2c3d4e5f67890` |
| `route-` | Global route | `route-abc123` |
| `vault-` | Vault | `vault-team` |
| `cp-` | Checkpoint | `cp-20260530-abc12345` |
| `ln-` | Lineage hash id | `ln-deadbeef` |

---

**Related documents:** [OVERVIEW.md](OVERVIEW.md) · [HOW_IT_WORKS.md](../HOW_IT_WORKS.md) · [SYSTEM_COMPONENTS.md](SYSTEM_COMPONENTS.md)
