pub const VAULT_SUBDIRS: &[&str] = &[
    "metadata/repos",
    "metadata/checkpoints",
    "repositories",
    "checkpoints",
    "replication",
    "synchronization",
    "trust",
    "bundles",
    "policies/repos",
    "logs",
];

pub use crate::{Repo, Vault};

pub fn mirror_path(vault: &Vault, repo: &Repo) -> std::path::PathBuf {
    vault
        .path
        .join("repositories")
        .join(format!("{}.git", repo.id))
}
