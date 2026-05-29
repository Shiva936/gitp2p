use gitp2p_global_discovery::discover_replicas;
use gitp2p_metadata::{Repo, Result};
use gitp2p_routing::build_global_route;
use gitp2p_vault::App;

use crate::multi::recover_from_best_peer;

#[derive(Clone, Debug)]
pub struct GlobalRecoverySource {
    pub domain: String,
    pub peer_id: String,
    pub checkpoint_id: String,
    pub score: u64,
}

pub fn discover_recovery_sources(
    app: &App,
    repo_id: &str,
) -> Result<Vec<GlobalRecoverySource>> {
    let mut sources = Vec::new();
    for candidate in crate::multi::select_recovery_source(app, repo_id, "auto")? {
        sources.push(GlobalRecoverySource {
            domain: "local".into(),
            peer_id: candidate.peer_id.clone(),
            checkpoint_id: candidate.checkpoint.id.clone(),
            score: candidate.score,
        });
    }
    for replica in discover_replicas(app, Some(repo_id))? {
        sources.push(GlobalRecoverySource {
            domain: replica.source.clone(),
            peer_id: replica.source.clone(),
            checkpoint_id: replica.id.clone(),
            score: 500,
        });
    }
    sources.sort_by(|a, b| b.score.cmp(&a.score));
    sources.dedup_by(|a, b| a.peer_id == b.peer_id && a.checkpoint_id == b.checkpoint_id);
    Ok(sources)
}

pub fn recover_global(
    app: &App,
    repo: &Repo,
    domain: Option<&str>,
    target: Option<std::path::PathBuf>,
) -> Result<()> {
    let _route = build_global_route(
        app,
        domain.unwrap_or("remote"),
    )?;
    let sources = discover_recovery_sources(app, &repo.id)?;
    if sources.is_empty() {
        return Err(gitp2p_metadata::AppError::new(
            "no global recovery sources found",
        ));
    }
    let best = &sources[0];
    if best.domain == "local" {
        return recover_from_best_peer(app, repo, "auto", None, target);
    }
    recover_from_best_peer(app, repo, &best.peer_id, None, target)
}

pub fn recover_sources(app: &App, repo_id: &str) -> Result<Vec<GlobalRecoverySource>> {
    discover_recovery_sources(app, repo_id)
}

pub fn format_recovery_sources(sources: &[GlobalRecoverySource]) -> String {
    let mut out = String::from("domain\tpeer\tcheckpoint\tscore\n");
    for source in sources {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            source.domain, source.peer_id, source.checkpoint_id, source.score
        ));
    }
    out
}

pub use GlobalRecoverySource as RecoverySourceEntry;
