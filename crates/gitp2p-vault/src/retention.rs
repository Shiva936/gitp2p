use std::fs;

use gitp2p_metadata::{AppError, Checkpoint, Policy, Repo, Result};
use gitp2p_metadata::git::git;
use gitp2p_metadata::util::contains_csv;

use crate::app::{checkpoints_for_repo, read_checkpoint, write_repo};
use crate::layout::mirror_path;
use crate::App;

pub struct PruneReport {
    pub removed: Vec<String>,
    pub kept: Vec<String>,
}

pub fn enforce_retention(
    app: &App,
    repo: &Repo,
    policy: &Policy,
    dry_run: bool,
) -> Result<PruneReport> {
    prune_checkpoints(app, repo, policy, None, None, dry_run)
}

pub fn prune_checkpoints(
    app: &App,
    repo: &Repo,
    policy: &Policy,
    keep: Option<usize>,
    older_than_days: Option<u64>,
    dry_run: bool,
) -> Result<PruneReport> {
    let vault = app.find_vault(&repo.vault_id)?;
    let mut checkpoints = checkpoints_for_repo(app, &repo.id)?;
    if checkpoints.is_empty() {
        return Ok(PruneReport {
            removed: Vec::new(),
            kept: Vec::new(),
        });
    }

    let max_keep = keep.or_else(|| {
        policy
            .retention_max_checkpoints
            .parse::<usize>()
            .ok()
            .filter(|v| *v > 0)
    });
    let max_age = older_than_days.or_else(|| {
        policy
            .retention_max_age_days
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0)
    });
    let now = gitp2p_metadata::util::timestamp()
        .parse::<u64>()
        .unwrap_or(0);

    let mut kept = Vec::new();
    let mut removed = Vec::new();

    for checkpoint in &checkpoints {
        if contains_csv(&policy.protected_checkpoint_ids, &checkpoint.id) {
            kept.push(checkpoint.id.clone());
        }
    }

    checkpoints.retain(|cp| !kept.contains(&cp.id));

    if let Some(max_age) = max_age {
        checkpoints.retain(|cp| {
            let age_ok = cp
                .created_at
                .parse::<u64>()
                .map(|created| now.saturating_sub(created) <= max_age * 86_400)
                .unwrap_or(true);
            if !age_ok {
                removed.push(cp.id.clone());
            }
            age_ok
        });
    }

    if let Some(max_keep) = max_keep {
        if checkpoints.len() > max_keep {
            let to_remove = checkpoints.len() - max_keep;
            for cp in checkpoints.drain(..to_remove) {
                removed.push(cp.id);
            }
        }
    }

    for cp in &checkpoints {
        kept.push(cp.id.clone());
    }

    if dry_run {
        return Ok(PruneReport { removed, kept });
    }

    for id in &removed {
        let cp_path = vault
            .path
            .join("metadata")
            .join("checkpoints")
            .join(id);
        if cp_path.exists() {
            fs::remove_file(&cp_path)?;
        }
        let mirror = mirror_path(&vault, repo);
        if mirror.exists() {
            let ref_name = format!("refs/gitp2p/checkpoints/{id}");
            let _ = git(["update-ref", "-d", &ref_name], Some(&mirror));
        }
    }

    if let Some(latest) = kept.last() {
        let mut updated = repo.clone();
        updated.latest_checkpoint = latest.clone();
        write_repo(&vault, &updated)?;
    }

    Ok(PruneReport { removed, kept })
}
