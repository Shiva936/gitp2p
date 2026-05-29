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

pub use gitp2p_metadata::{Repo, Vault};

pub fn mirror_path(vault: &Vault, repo: &Repo) -> std::path::PathBuf {
    vault
        .path
        .join("repositories")
        .join(format!("{}.git", repo.id))
}
