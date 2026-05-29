# gitp2p

Local-first CLI for protected Git vaults, signed recovery checkpoints, trusted peer synchronization, and decentralized global federation.

## Project Overview

gitp2p wraps your Git repositories in **vaults**, creates **cryptographically signed checkpoints** for sovereign recovery, and syncs with **trusted peers** over filesystem, LAN, or QUIC—without requiring GitHub or any centralized host.

Version **7.0.0** adds **enterprise infrastructure** (organizations, governance, audit, compliance) on top of the **v6 autonomous runtime** and **v5 global federation**.

## Problem Statement

Centralized Git hosting creates single points of failure. Traditional backups lack verifiable trust boundaries. Teams on airgapped, LAN, or cross-organizational networks need sync that is:

- **Local-first** — you own the data
- **Recoverable** — immutable signed checkpoints, not just reflog
- **Trust-aware** — explicit peer approval and policy zones
- **Federation-ready** — cross-domain sync without mandatory public registries

gitp2p addresses these gaps in a single CLI tool.

## Core Features

| Area | Capabilities |
|------|-------------|
| **Vaults** | Sovereign repo containers with policies and retention |
| **Checkpoints** | Signed immutable recovery points |
| **Trust** | Peer approval, trust zones, delegation chains |
| **Sync** | Filesystem, mDNS/QUIC LAN, mesh multi-hop |
| **Offline** | Bundles, portable vault packages, media export |
| **Verification** | Peers, checkpoints, manifests, lineage, Merkle, CAS |
| **Federation** | Domains, gateways, peering, global routes, mobility |

## Architecture Summary

gitp2p is an **8-package** Rust workspace (7 libraries under `libs/` plus `cli/` at the repo root). The CLI dispatches to library crates; optional v5–v7 layers compile via Cargo features (`federation`, `runtime`, `enterprise`). All state lives under `GITP2P_HOME`. Federation uses signed KV metadata with gateway-mediated cross-domain discovery—no embedded database, no mandatory cloud.

Full architecture: [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md)

## Quick Start

```bash
cargo build -p cli

gitp2p vault create myteam
gitp2p repo add myteam .
gitp2p checkpoint
gitp2p recover repo --target ./recovered --auto-recover
```

## Installation

Build from source (requires Rust stable and Git):

```bash
git clone <repository-url> gitp2p
cd gitp2p
cargo build -p cli
# binary: target/debug/gitp2p
```

See [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) for prerequisites, configuration, and verification.

## Usage Examples

| Goal | Starting point |
|------|----------------|
| First vault and checkpoint | [Getting Started](docs/GETTING_STARTED.md#first-run) |
| Trusted peer sync | `peers discover` → `trust add` → `sync --peer` |
| Offline bundle | `bundle create` → `recover --offline` |
| Mesh / relay | `relay enable` → `route inspect` → `sync` |
| Global federation (v5) | `domain create` → `gateway create` → `sync --domain` |
| Verify records | `verify domain\|gateway\|peering\|delegation\|route` |

Detailed command walkthroughs: [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)

## Documentation Index

### Root

| Document | Description |
|----------|-------------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [docs/SECURITY.md](docs/SECURITY.md) | Security policy and vulnerability reporting |

### User guides

| Document | Description |
|----------|-------------|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Full onboarding |
| [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) | Concepts and mental model |
| [docs/FAQs.md](docs/FAQs.md) | Frequently asked questions |

### Architecture

| Document | Description |
|----------|-------------|
| [docs/architecture/OVERVIEW.md](docs/architecture/OVERVIEW.md) | Architecture entry point |
| [docs/architecture/SYSTEM_COMPONENTS.md](docs/architecture/SYSTEM_COMPONENTS.md) | Crate catalog |
| [docs/architecture/DATA_FLOW.md](docs/architecture/DATA_FLOW.md) | Sync and checkpoint pipelines |
| [docs/architecture/EXECUTION_MODEL.md](docs/architecture/EXECUTION_MODEL.md) | Runtime behavior |
| [docs/architecture/STORAGE.md](docs/architecture/STORAGE.md) | Persistence layout |
| [docs/architecture/NETWORKING.md](docs/architecture/NETWORKING.md) | Transports and federation |
| [docs/architecture/SECURITY_ARCHITECTURE.md](docs/architecture/SECURITY_ARCHITECTURE.md) | Technical security design |
| [docs/architecture/DEPLOYMENT_ARCHITECTURE.md](docs/architecture/DEPLOYMENT_ARCHITECTURE.md) | Deployment and env vars |
| [docs/architecture/FAILURE_RECOVERY.md](docs/architecture/FAILURE_RECOVERY.md) | Resilience and recovery |
| [docs/architecture/SCALING.md](docs/architecture/SCALING.md) | Limits and capacity |
| [docs/architecture/EXTENSIBILITY.md](docs/architecture/EXTENSIBILITY.md) | Extension patterns |
| [docs/architecture/DECISIONS.md](docs/architecture/DECISIONS.md) | Architectural decisions |
| [docs/architecture/GLOSSARY.md](docs/architecture/GLOSSARY.md) | Terminology |

## Project Status

- **Version:** 5.0.0
- **Crates:** 27 (Rust workspace)
- **Transport:** Filesystem-first; optional mDNS + QUIC/TLS
- **Federation:** v5 domains/gateways via KV simulation (wire protocol future work)
- **Tests:** `cargo test` — unit and integration tests included

## Contributing

We welcome issues and pull requests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

Report vulnerabilities privately. See [SECURITY.md](docs/SECURITY.md).

## License

MIT License. See [Cargo.toml](Cargo.toml) (`license = "MIT"`).
