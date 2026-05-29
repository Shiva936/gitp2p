# Security Architecture

Technical security design for gitp2p.

## Trust Model

- **Local identity is root of trust** — Ed25519 key in `~/.gitp2p/identity` signs checkpoints, sessions, federation records, delegations.
- **Peers are explicitly approved** — Discovery alone does not grant sync rights; `trust approve` required.
- **Trust zones constrain repos** — Per-repo labels gate export, sync push, and checkpoint actions.
- **Federation trust is delegated** — Cross-domain access requires valid peering + optional delegation chain.
- **No implicit global trust** — Remote domains appear in discovery but are not trusted until peering and delegation validate.

## Authentication

- **Peer identity** — Derived from Ed25519 public key; validated on discover (`validate_peer_identity`).
- **Session authenticity** — Sessions signed by initiating identity; verified with peer public key.
- **Federation records** — Domains, gateways, peerings signed by creating identity.

## Authorization

Trust zones (`gitp2p-trust/zones.rs`) govern repo actions:

| Zone | Typical restriction |
|------|---------------------|
| `trusted` | Full allow |
| `readonly` | Deny sync push |
| `protected` / `ai-generated` | Push requires approval |
| `experimental` | Deny export; push requires approval |
| `shared` | Push denied for untrusted peers |
| `quarantined` | Deny all |

Vault/repo policies merge via `merged_policy`.

## Encryption

- **QUIC + TLS** — Optional encrypted transport for LAN/internet peer sync.
- **Bundle encryption** — Optional with `GITP2P_BUNDLE_KEY` and `--encrypt` flag.
- **At-rest** — Identity private key stored as KV plaintext on disk; operator must protect filesystem permissions.

## Key Management

- Generated on first run via `ensure_identity`.
- Export/import: `gitp2p id export` / `gitp2p id import`.
- TLS certs generated under `~/.gitp2p/tls/` for QUIC (rcgen).
- No HSM integration in v5; filesystem permissions are the primary control.

## Security Boundaries

```text
┌─────────────────────────────────────┐
│  GITP2P_HOME (operator-controlled)  │
│  identity · vaults · federation    │
└─────────────────────────────────────┘
           │ signed records
           ▼
┌─────────────────────────────────────┐
│  Trusted peers (explicit approve)    │
└─────────────────────────────────────┘
           │ peering + delegation
           ▼
┌─────────────────────────────────────┐
│  Remote federation domains           │
└─────────────────────────────────────┘
```

## Attack Surfaces

| Surface | Risk | Mitigation |
|---------|------|------------|
| `GITP2P_HOME` tampering | Forged metadata | Signatures + verify commands |
| Malicious peer | Data exfiltration | Trust zones, approve workflow |
| LAN mDNS spoofing | Fake peer discovery | Identity validation before trust |
| Delegation chain abuse | Cross-domain overreach | `validate_delegation_chain`, revoke |
| Bundle import | Supply chain | `bundle validate`, manifest verify |
| Dependency vulnerabilities | RCE via crates | `cargo audit`, pinned workspace deps |

---

**Related documents:** [SECURITY.md](../SECURITY.md) · [NETWORKING.md](NETWORKING.md) · [GLOSSARY.md](GLOSSARY.md)
