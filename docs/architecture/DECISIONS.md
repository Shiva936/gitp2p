# Architectural Decisions

Record of major design choices for gitp2p.

## Major Decisions

### ADR-001: Rust workspace with focused crates

**Decision:** Split functionality into 27 single-purpose crates behind one CLI.

**Alternatives:** Monolith binary; microservices.

**Tradeoffs:** More boilerplate, clearer boundaries, independent testing, avoids circular deps.

**Status:** Superseded by ADR-008 (v7 libs consolidation).

---

### ADR-008: 8-package `libs/` workspace (v7)

**Decision:** Consolidate 45 workspace members into 7 libraries under `libs/` plus `cli/` at repo root. Optional v5–v7 layers compile via Cargo features on the CLI (`federation`, `runtime`, `enterprise`).

**Alternatives:** Keep 45-crate layout; single monolith crate.

**Tradeoffs:** Fewer workspace members and clearer layer boundaries; larger modules within each library; routing/relay/topology moved into `gitp2p-federation` to avoid sync↔federation cycles.

**Status:** Accepted (v7.0.0).

---

### ADR-002: Filesystem-first peer transport

**Decision:** Default sync discovers peers via shared `GITP2P_HOME` paths (NAS, WSL, airgap).

**Alternatives:** GitHub-only; mandatory central server.

**Tradeoffs:** Zero infra for small teams; requires path sharing or LAN for remote peers.

**Status:** Accepted; QUIC/mDNS additive (v2).

---

### ADR-003: KV metadata store

**Decision:** Metadata stored as key-value text files, not SQLite/JSON DB.

**Alternatives:** Embedded SQL; single JSON config.

**Tradeoffs:** Human-readable, git-diffable, no migration framework; scan cost at scale.

**Status:** Accepted.

---

### ADR-004: Signed checkpoints as recovery unit

**Decision:** Immutable signed checkpoints, not live Git refs alone, anchor recovery and sync.

**Alternatives:** Raw `git push` mirrors; tag-only recovery.

**Tradeoffs:** Extra metadata layer; strong audit trail and offline verify.

**Status:** Accepted (v1).

---

### ADR-005: Trust zones per repository

**Decision:** Repo-level zones gate sync/export/checkpoint without per-file ACLs.

**Alternatives:** Vault-only policy; external IAM.

**Tradeoffs:** Simple model; coarse-grained control.

**Status:** Accepted (v1).

---

### ADR-006: Decentralized federation without central registry (v5)

**Decision:** Domains peer via gateways; discovery aggregates local + exchanged caches.

**Alternatives:** Public federation directory; blockchain registry.

**Tradeoffs:** Sovereign domains; operator must establish peering explicitly.

**Status:** Accepted (v5.0.0).

---

### ADR-007: Gateway exchange via KV files (v5 interim)

**Decision:** Route/discovery exchange written to gateway `exchange/` dirs before wire protocol.

**Alternatives:** Immediate QUIC gateway protocol.

**Tradeoffs:** Deterministic CI/tests; not production WAN-ready alone.

**Status:** Accepted interim; wire protocol is future work.

---

### ADR-008: Delegation chains in gitp2p-trust

**Decision:** Cross-domain trust via signed delegation linked lists, validated deterministically.

**Alternatives:** X.509 PKI; capability tokens.

**Tradeoffs:** Consistent with existing Ed25519 model; chain depth limited in validator.

**Status:** Accepted (v5).

## Historical Context

- v1–v2 established vault + peer trust on filesystem transport.
- v3 added portable offline federation (bundles, lineage).
- v4 added mesh routing and relay.
- v4.5 formalized identity/content verification (CAS, Merkle).
- v5 answered **WHERE** with domains, gateways, peering, global sync/recovery.
- v6 added autonomous runtime (policies, agents, health).
- v7 added enterprise org/governance/audit/compliance.
- v7(ADR-008) consolidated crates into 8 packages under `libs/`.

## Future Reassessment Criteria

Revisit decisions when:

- Wire gateway protocol ships (ADR-007).
- Metadata record count exceeds comfortable KV scan limits (ADR-003).
- Enterprise deployments require centralized policy (ADR-006).
- Plugin/dynamic extension demand emerges (ADR-001).

---

**Related documents:** [OVERVIEW.md](OVERVIEW.md) · [EXTENSIBILITY.md](EXTENSIBILITY.md) · [GLOSSARY.md](GLOSSARY.md)
