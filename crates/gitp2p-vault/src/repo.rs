use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use gitp2p_metadata::{AppError, Repo, Result, Vault};
use gitp2p_metadata::git::ensure_git_repo;
use gitp2p_metadata::util::{stable_id, timestamp};
use gitp2p_trust::is_valid_zone;

use crate::app::{read_repo, write_repo};
use crate::App;

pub fn add_repo(
    app: &App,
    vault: &Vault,
    path_arg: Option<String>,
    zone: &str,
) -> Result<Repo> {
    if !is_valid_zone(zone) {
        return Err(AppError::new(format!("invalid trust zone '{zone}'")));
    }
    let repo_path = match path_arg {
        Some(path) => PathBuf::from(path),
        None => env::current_dir()?,
    }
    .canonicalize()?;
    ensure_git_repo(&repo_path)?;
    let name = repo_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| AppError::new("repository path has no final name"))?
        .to_string();
    let id = format!("repo-{}", stable_id(&repo_path.to_string_lossy()));
    if app.all_repos()?.iter().any(|repo| repo.id == id) {
        return Err(AppError::new(format!(
            "repository '{}' is already registered",
            repo_path.display()
        )));
    }
    let repo = Repo {
        id: id.clone(),
        name: name.clone(),
        path: repo_path,
        vault_id: vault.id.clone(),
        trust_zone: zone.to_string(),
        sync_state: "registered".to_string(),
        latest_checkpoint: String::new(),
        created_at: timestamp(),
    };
    write_repo(vault, &repo)?;
    Ok(repo)
}

pub fn remove_repo(app: &App, repo: &Repo, yes: bool) -> Result<()> {
    if !yes {
        return Err(AppError::new(
            "repository removal requires --yes; repository contents are preserved",
        ));
    }
    let vault = app.find_vault(&repo.vault_id)?;
    fs::remove_file(vault.path.join("metadata").join("repos").join(&repo.id))?;
    Ok(())
}

pub fn register_imported_repo(vault: &Vault, repo: Repo) -> Result<Repo> {
    write_repo(vault, &repo)?;
    Ok(repo)
}
