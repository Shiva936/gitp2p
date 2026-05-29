# Contributing to gitp2p

Thank you for your interest in contributing. This document explains how to participate effectively.

## Contribution Philosophy

- **Small, focused changes** are easier to review and merge.
- **Tests are required** for behavior changes; run `cargo test` before submitting.
- **Match existing patterns** — extend crates rather than duplicating logic.
- **Document user-visible changes** in `docs/` alongside code.
- **Security issues** are reported privately — see [SECURITY.md](docs/SECURITY.md).

## Development Environment

- **Rust** — Stable toolchain (2021 edition)
- **Cargo** — Build and test runner
- **Git** — Version control and repo tests
- **OS** — Linux, macOS, or WSL2 recommended

## Local Setup

```bash
git clone <repository-url> gitp2p
cd gitp2p
cargo build -p gitp2p-cli
cargo test
```

The CLI binary is at `target/debug/gitp2p`.

## Branch Strategy

- Create feature branches from the default branch.
- Use descriptive branch names: `feat/federation-foo`, `fix/sync-error`, `docs/getting-started`.
- Keep branches scoped to one logical change when possible.

## Commit Standards

- Use imperative mood: "Add gateway inspect command" not "Added..."
- First line ≤ 72 characters; optional body explains **why**.
- Reference issues in the body when applicable.

Example:

```text
Add peering revocation audit trail

Peering revoke now re-signs manifest with revoked state so
verify commands can detect revoked peerings deterministically.
```

## Pull Request Process

1. Fork and branch from latest default branch.
2. Implement change with tests.
3. Run `cargo test` and ensure it passes.
4. Update relevant documentation in `docs/` if behavior changed.
5. Open a PR with:
   - Summary of what and why
   - Test plan (commands run)
   - Breaking changes noted explicitly
6. Address review feedback.
7. Maintainer merges when CI and review are satisfied.

## Coding Standards

- **Minimal scope** — Smallest correct diff; avoid unrelated refactors.
- **Reuse existing abstractions** — KV helpers, signing, `App` API.
- **No circular crate dependencies** — e.g. `gitp2p-trust` must not depend on `gitp2p-vault`.
- **New v5 federation features** belong in federation crates, not CLI internals.
- **CLI handlers** go in `extended.rs` following existing patterns.
- Follow Rust idioms; avoid unnecessary wrappers or abstraction layers.

## Testing Requirements

- Unit tests in crate `src/` or `tests/` directories.
- Integration tests for multi-step workflows (see `crates/gitp2p-cli/tests/`).
- Use temp directories and isolated `GITP2P_HOME` for federation tests.
- All tests must pass: `cargo test`

## Documentation Requirements

When changing user-visible behavior, update:

- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) — if setup or commands change
- [docs/HOW_IT_WORKS.md](docs/HOW_IT_WORKS.md) — if concepts change
- [docs/architecture/](docs/architecture/) — if architecture changes
- [docs/FAQs.md](docs/FAQs.md) — if a recurring question is answered

Do not modify files under `plans/` as part of routine contributions unless explicitly requested.

## Release Process

1. Ensure `cargo test` passes on the release branch.
2. Bump `workspace.package.version` in root [Cargo.toml](Cargo.toml).
3. Update [README.md](README.md) project status if needed.
4. Tag release (maintainer).
5. Publish release notes summarizing user-facing changes.

## Maintainer Responsibilities

- Review PRs for correctness, tests, and documentation.
- Triage security reports per [SECURITY.md](docs/SECURITY.md).
- Keep default branch merge-ready.
- Enforce code of conduct ([CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)).
- Coordinate releases and version bumps.

---

**Related documents:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [docs/SECURITY.md](docs/SECURITY.md) · [docs/architecture/EXTENSIBILITY.md](docs/architecture/EXTENSIBILITY.md)
