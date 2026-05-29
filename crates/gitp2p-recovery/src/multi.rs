use gitp2p_metadata::{read_kv, Checkpoint, Result};
use gitp2p_metadata::git::git_fsck_ok;
use gitp2p_metadata::optional_field;
use gitp2p_trust::verify_checkpoint;
use gitp2p_vault::{layout::mirror_path, App};

pub struct RecoveryCandidate {
    pub peer_id: String,
    pub checkpoint: Checkpoint,
    pub score: u64,
}

pub fn select_recovery_source(
    app: &App,
    repo_id: &str,
    peer_spec: &str,
) -> Result<Vec<RecoveryCandidate>> {
    let peer_ids: Vec<String> = if peer_spec == "auto" {
        app.all_peers()?
            .into_iter()
            .filter(|peer| matches!(peer.trust_state.as_str(), "trusted" | "protected"))
            .map(|peer| peer.id)
            .collect()
    } else {
        peer_spec.split(',').map(|s| s.trim().to_string()).collect()
    };

    let mut candidates = Vec::new();
    for peer_id in peer_ids {
        let peer = app.find_peer(&peer_id)?;
        let remote_app = App::with_home(peer.home.clone());
        let remote_repo = match remote_app.find_repo(Some(repo_id)) {
            Ok(repo) => repo,
            Err(_) => continue,
        };
        let remote_vault = remote_app.find_vault(&remote_repo.vault_id)?;
        let mirror = mirror_path(&remote_vault, &remote_repo);
        if !mirror.exists() {
            continue;
        }
        let checkpoint = gitp2p_vault::latest_checkpoint(&remote_app, repo_id)?;
        if verify_checkpoint(&checkpoint, &peer.public_key).is_err() {
            continue;
        }
        if !git_fsck_ok(&mirror)? {
            continue;
        }
        let created = checkpoint.created_at.parse::<u64>().unwrap_or(0);
        let replication_bonus = replication_state_for(app, &peer_id, repo_id)
            .map(|state| {
                if state.get("propagation_state").map(String::as_str) == Some("complete") {
                    1000
                } else {
                    0
                }
            })
            .unwrap_or(0);
        candidates.push(RecoveryCandidate {
            peer_id: peer.id,
            checkpoint,
            score: created + replication_bonus,
        });
    }
    candidates.sort_by(|a, b| b.score.cmp(&a.score));
    Ok(candidates)
}

pub fn recover_from_best_peer(
    app: &App,
    repo: &gitp2p_metadata::Repo,
    peer_spec: &str,
    checkpoint_id: Option<&str>,
    target: Option<std::path::PathBuf>,
) -> Result<()> {
    let candidates = select_recovery_source(app, &repo.id, peer_spec)?;
    if candidates.is_empty() {
        return Err(gitp2p_metadata::AppError::new(
            "no valid peer recovery sources found",
        ));
    }
    if candidates.len() > 1 && peer_spec.contains(',') {
        println!("recovery source comparison:");
        for candidate in &candidates {
            println!(
                "  peer={} checkpoint={} score={}",
                candidate.peer_id, candidate.checkpoint.id, candidate.score
            );
        }
    }
    let best = &candidates[0];
    let cp = checkpoint_id.unwrap_or(&best.checkpoint.id);
    super::peer::recover_from_peer(app, repo, &best.peer_id, Some(cp), target)
}

fn replication_state_for(
    app: &App,
    peer_id: &str,
    repo_id: &str,
) -> Result<std::collections::BTreeMap<String, String>> {
    for vault in app.all_vaults()? {
        let path = vault
            .path
            .join("replication")
            .join(format!("{peer_id}-{repo_id}"));
        if path.exists() {
            return read_kv(&path);
        }
    }
    Err(gitp2p_metadata::AppError::new("replication state not found"))
}

pub fn best_checkpoint_peers(app: &App) -> Result<Vec<(String, String, String)>> {
    let mut rows = Vec::new();
    for vault in app.all_vaults()? {
        let dir = vault.path.join("replication");
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let map = read_kv(&entry.path())?;
                rows.push((
                    optional_field(&map, "peer_id"),
                    optional_field(&map, "repo_id"),
                    optional_field(&map, "checkpoint_id"),
                ));
            }
        }
    }
    Ok(rows)
}
