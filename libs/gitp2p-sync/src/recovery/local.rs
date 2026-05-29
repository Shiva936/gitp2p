use gitp2p_core::{Checkpoint, Repo, Result};
use gitp2p_core::git::{git, git_fsck_ok};
use gitp2p_core::{layout::mirror_path, latest_checkpoint, App};

use crate::doctor::{prepare_recovery_target, working_tree_needs_recovery};

pub fn recover_local(
    app: &App,
    repo: &Repo,
    checkpoint: Option<&Checkpoint>,
    target: Option<std::path::PathBuf>,
    auto_recover: bool,
) -> Result<()> {
    if auto_recover && working_tree_needs_recovery(repo)? {
        println!("auto-recover: working tree failed integrity check, restoring from vault mirror");
    }
    let vault = app.find_vault(&repo.vault_id)?;
    let checkpoint = match checkpoint {
        Some(cp) => {
            if cp.repo_id != repo.id {
                return Err(gitp2p_core::AppError::new(
                    "checkpoint does not belong to repository",
                ));
            }
            cp.clone()
        }
        None => latest_checkpoint(app, &repo.id)?,
    };
    let target = target.unwrap_or_else(|| repo.path.clone());
    let mirror = mirror_path(&vault, repo);
    if !mirror.exists() {
        return Err(gitp2p_core::AppError::new(
            "repository mirror is missing; create a checkpoint first",
        ));
    }
    prepare_recovery_target(&target)?;
    git(
        [
            "clone",
            mirror.to_string_lossy().as_ref(),
            target.to_string_lossy().as_ref(),
        ],
        None,
    )?;
    git(["checkout", &checkpoint.commit], Some(&target))?;
    git(["fsck", "--full"], Some(&target))?;
    if !git_fsck_ok(&target)? {
        return Err(gitp2p_core::AppError::new(
            "recovered repository failed integrity validation",
        ));
    }
    println!("repository recovered");
    println!("  repository: {}", repo.name);
    println!("  checkpoint: {}", checkpoint.id);
    println!("  target: {}", target.display());
    Ok(())
}
