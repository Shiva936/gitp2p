use std::path::Path;

use gitp2p_core::{git, Result, Repo};
use gitp2p_core::{layout::mirror_path, App};

pub struct NegotiationResult {
    pub local_head: String,
    pub remote_head: String,
    pub refs_to_sync: Vec<String>,
    pub incremental: bool,
}

pub fn negotiate_refs(
    app: &App,
    repo: &Repo,
    remote_mirror: Option<&Path>,
) -> Result<NegotiationResult> {
    let vault = app.find_vault(&repo.vault_id)?;
    let local_mirror = mirror_path(&vault, repo);
    let local_head = git_head(&local_mirror)?;
    let remote_head = remote_mirror
        .map(git_head)
        .transpose()?
        .unwrap_or_default();
    let incremental = !remote_head.is_empty() && remote_head != local_head;
    let refs_to_sync = if incremental {
        vec![format!("refs/heads/{}", repo.name)]
    } else {
        vec!["--all".to_string()]
    };
    Ok(NegotiationResult {
        local_head,
        remote_head,
        refs_to_sync,
        incremental,
    })
}

fn git_head(mirror: &Path) -> Result<String> {
    let output = git::git_output(["rev-parse", "HEAD"], Some(mirror))?;
    Ok(output.trim().to_string())
}
