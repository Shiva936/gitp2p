use gitp2p_metadata::{AppError, Checkpoint, Repo, RepoAction, Result};
use gitp2p_metadata::git::{ensure_git_repo, git, git_output};
use gitp2p_metadata::util::{append_log, compact_timestamp, timestamp};
use gitp2p_trust::{
    enforce_repo_action, merged_policy, sign_checkpoint, zone_requires_policy_approval,
};
use gitp2p_trust::peer_is_trusted;

use crate::app::{read_checkpoint, write_checkpoint, write_repo};
use crate::layout::mirror_path;
use crate::retention::enforce_retention;
use crate::App;

pub fn create_checkpoint(
    app: &App,
    repo_ref: Option<&str>,
    enforce_retention_flag: bool,
    requires_approval: bool,
    peer_trusted: bool,
) -> Result<Checkpoint> {
    let mut repo = app.find_repo(repo_ref)?;
    let vault = app.find_vault(&repo.vault_id)?;
    let policy = merged_policy(&vault, Some(&repo.id))?;
    let needs_approval = requires_approval
        || zone_requires_policy_approval(&policy, &repo.trust_zone);
    enforce_repo_action(
        &repo,
        RepoAction::Checkpoint,
        needs_approval,
        peer_trusted,
    )?;
    ensure_git_repo(&repo.path)?;
    git(["fsck", "--full"], Some(&repo.path))?;
    let mirror = mirror_path(&vault, &repo);
    if mirror.exists() {
        git(
            [
                "remote",
                "set-url",
                "origin",
                repo.path.to_string_lossy().as_ref(),
            ],
            Some(&mirror),
        )?;
        git(["remote", "update", "--prune"], Some(&mirror))?;
    } else {
        git(
            [
                "clone",
                "--mirror",
                repo.path.to_string_lossy().as_ref(),
                mirror.to_string_lossy().as_ref(),
            ],
            None,
        )?;
    }
    let commit = git_output(["rev-parse", "HEAD"], Some(&repo.path))?;
    let commit = commit.trim().to_string();
    let parent = repo.latest_checkpoint.clone();
    let id = format!(
        "cp-{}-{}",
        compact_timestamp(),
        &commit[..12.min(commit.len())]
    );
    let ref_name = format!("refs/gitp2p/checkpoints/{id}");
    git(["update-ref", &ref_name, &commit], Some(&mirror))?;
    let mut checkpoint = Checkpoint {
        id: id.clone(),
        repo_id: repo.id.clone(),
        vault_id: vault.id.clone(),
        commit,
        parent,
        created_at: timestamp(),
        status: "verified".to_string(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let identity = app.ensure_identity()?;
    sign_checkpoint(&identity, &mut checkpoint)?;
    write_checkpoint(&vault, &checkpoint)?;
    repo.sync_state = "checkpointed".to_string();
    repo.latest_checkpoint = id;
    write_repo(&vault, &repo)?;
    append_log(
        &vault,
        &format!("checkpoint repo={} id={}", repo.id, repo.latest_checkpoint),
    )?;
    if enforce_retention_flag {
        enforce_retention(app, &repo, &policy, false)?;
    }
    Ok(checkpoint)
}

pub fn copy_checkpoint_if_missing(vault: &gitp2p_metadata::Vault, checkpoint: &Checkpoint) -> Result<()> {
    let path = vault
        .path
        .join("metadata")
        .join("checkpoints")
        .join(&checkpoint.id);
    if path.exists() {
        return Ok(());
    }
    let mut copy = checkpoint.clone();
    copy.status = "replicated-verified".to_string();
    write_checkpoint(vault, &copy)
}

pub fn checkpoint_lineage(app: &App, checkpoint: &Checkpoint) -> Result<String> {
    let mut chain = vec![checkpoint.id.clone()];
    let mut current = checkpoint.clone();
    while !current.parent.is_empty() {
        chain.push(current.parent.clone());
        let (_, _, parent) = app.find_checkpoint(&current.parent)?;
        current = parent;
    }
    Ok(chain.join("->"))
}

pub fn default_peer_trusted(_app: &App) -> bool {
    false
}

pub fn peer_trusted_for_repo(_repo: &Repo, peer_trusted: bool) -> bool {
    peer_trusted
}

pub fn validate_checkpoint_for_sync(repo: &Repo, requires_approval: bool, peer_trusted: bool) -> Result<()> {
    enforce_repo_action(repo, RepoAction::SyncPush, requires_approval, peer_trusted)
}
