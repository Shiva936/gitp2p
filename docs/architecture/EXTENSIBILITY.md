# Extensibility

How to extend gitp2p with new capabilities.

## Plugin Systems

gitp2p has no dynamic plugin loader. Extensions are **compile-time workspace crates**.

## APIs

Primary extension surfaces:

| Surface | Location | Use |
|---------|----------|-----|
| `App` | `gitp2p-vault` | Home-scoped operations |
| KV helpers | `gitp2p-metadata` | New record types |
| Metadata models | `gitp2p-metadata/src/models.rs` | New structs |
| ID helpers | `gitp2p-identity` | New ID derivations |
| CLI handlers | `cli/src/extended.rs` | New commands |
| Verify pipeline | `gitp2p-verify` | New verify entry points |

## Extension Points

### New workspace crate

1. Add a module under the appropriate library in `libs/` (e.g. `libs/gitp2p-federation/src/`).
2. Register in root [Cargo.toml](Cargo.toml) `members` and `[workspace.dependencies]`.
3. Depend on `gitp2p-metadata` (+ `gitp2p-trust` / `gitp2p-vault` as needed).
4. Avoid circular dependencies (trust must not depend on vault).

### New CLI command

1. Add `Subcommand` enum variant in `main.rs`.
2. Implement handler in `extended.rs` or inline in `main.rs`.
3. Wire crate dependency in `cli/Cargo.toml`.

### New federation record type

1. Add model to `gitp2p-metadata`.
2. Add layout path in federation `layout.rs` or subsystem crate.
3. Sign with `sign_bytes`; verify in `gitp2p-verify`.
4. Add `verify <kind>` CLI if user-facing.

### New transport

Extend `gitp2p-sync` discovery/replication modules; respect `GITP2P_TRANSPORT`.

## Integration Patterns

- **Filesystem simulation** — Separate `GITP2P_HOME` directories for multi-node tests (see `cli/tests/lan_workflow.rs`).
- **Offline integration** — Bundles and vault packages for CI without network.
- **KV exchange** — Gateway manifest pattern for cross-domain metadata before wire protocol.

## Compatibility Rules

- Preserve existing KV field names; add new fields rather than rename.
- Empty signature fields remain valid for legacy records.
- Workspace version bumped in lockstep (`workspace.package.version`).
- New commands must not break existing v1–v4.5 workflows.
- Document new behavior in `docs/` before release.

---

**Related documents:** [SYSTEM_COMPONENTS.md](SYSTEM_COMPONENTS.md) · [DECISIONS.md](DECISIONS.md) · [CONTRIBUTING.md](../../CONTRIBUTING.md)
