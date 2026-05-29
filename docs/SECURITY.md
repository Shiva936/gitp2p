# Security Policy

Security expectations and vulnerability reporting for gitp2p.

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 5.0.x | Yes | Current release |
| 4.5.x | Best effort | Security fixes as feasible |
| 4.x and earlier | Unmaintained | Upgrade recommended |

## Reporting Vulnerabilities

**Do not** open public GitHub issues for security vulnerabilities.

Report privately via:

1. **GitHub Security Advisories** — Use "Report a vulnerability" on the repository Security tab.
2. **Email** — Contact repository maintainers directly if advisory access is unavailable.

Include:

- Description and impact
- Steps to reproduce
- Affected version(s)
- Suggested fix (if any)

We aim to acknowledge reports within **72 hours** and provide a remediation timeline within **14 days** for confirmed issues.

## Security Model

- **Local identity is root of trust** — Ed25519 key signs all authoritative records.
- **Peers require explicit approval** — `trust approve` before sync.
- **Trust zones** restrict repo actions (export, sync push, checkpoint).
- **Federation requires peering + valid delegation** — Remote domains are not implicitly trusted.
- **Verification is operator-triggered** — Use `verify` commands after sync/recovery.

Technical details: [architecture/SECURITY_ARCHITECTURE.md](architecture/SECURITY_ARCHITECTURE.md).

## Threat Model

| Threat | Mitigation |
|--------|------------|
| Untrusted peer pushing malicious data | Trust zones; approve workflow; signature verify |
| Tampered `GITP2P_HOME` metadata | Ed25519 signatures on records |
| LAN adversary spoofing mDNS peers | Identity validation before trust |
| Stolen identity file | Filesystem permissions; export/rotate identity |
| Malicious bundle import | `bundle validate`, manifest verify |
| Delegation chain abuse | Chain validator; revoke delegation |
| Dependency supply chain | `cargo audit`, pinned workspace versions |

**Out of scope:** Physical access to unlocked machine, compromised OS kernel, side-channel attacks on Ed25519.

## Security Features

- Ed25519 identity and signing (`gitp2p-trust`)
- Signed checkpoints, sessions, replication records
- Signed federation domains, gateways, peerings, delegations
- Trust zones including `quarantined` (deny all)
- Optional TLS + QUIC transport
- Optional bundle encryption (`GITP2P_BUNDLE_KEY`)
- Unified verify pipeline (`gitp2p verify domain|gateway|peering|delegation|route|...`)

## Secrets Management

| Secret | Location | Guidance |
|--------|----------|----------|
| Identity private key | `~/.gitp2p/identity` | Restrict file permissions (0600); backup via `id export` |
| TLS private key | `~/.gitp2p/tls/` | Auto-generated for QUIC |
| Bundle encryption key | `GITP2P_BUNDLE_KEY` env | Use secret manager; never commit |

Never commit identity files, TLS keys, or bundle keys to version control.

## Dependency Management

- Workspace pins crate versions in [Cargo.toml](../Cargo.toml).
- Run `cargo audit` periodically in CI or before releases.
- Report vulnerable dependencies through the same private channel.

## Incident Response

1. Confirm and reproduce the report.
2. Develop fix on private branch.
3. Release patched version with changelog.
4. Credit reporter (unless anonymous requested).
5. Publish advisory after fix is available.

## Disclosure Policy

- Coordinated disclosure preferred.
- Embargo until patch release unless active exploitation is detected.
- Public disclosure within **30 days** of report acknowledgment if no fix is possible, with mitigations documented.

---

**Related documents:** [architecture/SECURITY_ARCHITECTURE.md](architecture/SECURITY_ARCHITECTURE.md) · [FAQs.md](FAQs.md) · [CONTRIBUTING.md](../CONTRIBUTING.md)
