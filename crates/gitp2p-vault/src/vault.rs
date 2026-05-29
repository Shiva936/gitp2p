use std::fs;

use gitp2p_metadata::{write_kv, AppError, Result, Vault};
use gitp2p_metadata::util::{create_dir_all, stable_id, timestamp};
use gitp2p_trust::{default_policy, write_policy};

use crate::app::read_vault;
use crate::layout::VAULT_SUBDIRS;
use crate::App;

pub fn create_vault(app: &App, name: &str) -> Result<Vault> {
    let id = format!("vault-{}", stable_id(name));
    let path = app.vaults_dir().join(&id);
    if path.exists() {
        return Err(AppError::new(format!("vault '{name}' already exists")));
    }
    for dir in VAULT_SUBDIRS {
        create_dir_all(path.join(dir))?;
    }
    let created_at = timestamp();
    write_kv(
        &path.join("metadata").join("vault"),
        &[
            ("id", &id),
            ("name", name),
            ("created_at", &created_at),
            ("trust_status", "local-trusted"),
        ],
    )?;
    write_policy(&path.join("policies").join("default.policy"), &default_policy())?;
    read_vault(&path)
}

pub fn delete_vault(app: &App, reference: &str, yes: bool) -> Result<Vault> {
    if !yes {
        return Err(AppError::new(
            "vault deletion requires --yes because checkpoints will be removed",
        ));
    }
    let vault = app.find_vault(reference)?;
    fs::remove_dir_all(&vault.path)?;
    Ok(vault)
}

pub fn ensure_remote_vault(remote_app: &App, source: &Vault) -> Result<Vault> {
    let path = remote_app.vaults_dir().join(&source.id);
    if !path.exists() {
        for dir in VAULT_SUBDIRS {
            create_dir_all(path.join(dir))?;
        }
        write_kv(
            &path.join("metadata").join("vault"),
            &[
                ("id", &source.id),
                ("name", &source.name),
                ("created_at", &timestamp()),
                ("trust_status", "shared-replica"),
            ],
        )?;
        write_policy(
            &path.join("policies").join("default.policy"),
            &default_policy(),
        )?;
    } else {
        create_dir_all(path.join("replication"))?;
        create_dir_all(path.join("synchronization"))?;
    }
    read_vault(&path)
}
