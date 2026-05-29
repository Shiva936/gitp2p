use gitp2p_core::{Repo, RepoAction, Result};
use gitp2p_core::git::{git, git_fsck_ok};
use gitp2p_core::trust::{authorize_peer, enforce_repo_action, verify_checkpoint};
use gitp2p_core::{layout::mirror_path, latest_checkpoint, App};

use crate::doctor::prepare_recovery_target;

pub fn recover_from_peer(
    app: &App,
    repo: &Repo,
    peer_id: &str,
    checkpoint_id: Option<&str>,
    target: Option<std::path::PathBuf>,
) -> Result<()> {
    let peer = app.find_peer(peer_id)?;
    authorize_peer(&peer, false)?;
    enforce_repo_action(repo, RepoAction::Recover, false, true)?;
    let remote_app = App::with_home(peer.home.clone());
    let remote_repo = remote_app.find_repo(Some(&repo.id))?;
    let remote_vault = remote_app.find_vault(&remote_repo.vault_id)?;
    let checkpoint = match checkpoint_id {
        Some(id) => remote_app.find_checkpoint(id)?.2,
        None => latest_checkpoint(&remote_app, &repo.id)?,
    };
    verify_checkpoint(&checkpoint, &peer.public_key)?;
    let mirror = mirror_path(&remote_vault, &remote_repo);
    if !mirror.exists() {
        return Err(gitp2p_core::AppError::new(
            "peer mirror is missing for requested repository",
        ));
    }
    let target = target.unwrap_or_else(|| repo.path.clone());
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
            "peer recovery failed integrity validation",
        ));
    }
    println!("repository recovered from peer");
    println!("  peer: {}", peer.id);
    println!("  repository: {}", repo.name);
    println!("  checkpoint: {}", checkpoint.id);
    println!("  target: {}", target.display());
    Ok(())
}
