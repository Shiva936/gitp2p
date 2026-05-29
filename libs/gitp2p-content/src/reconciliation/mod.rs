use crate::{read_manifest, FederationManifest};
use gitp2p_core::{Repo, Result, Vault};
use gitp2p_core::util::timestamp;

#[derive(Clone, Debug)]
pub struct ReconciliationReport {
    pub action: String,
    pub conflicts: Vec<String>,
    pub merged_checkpoint: String,
}

pub fn reconcile_import(
    existing: Option<&Repo>,
    incoming: &FederationManifest,
) -> Result<ReconciliationReport> {
    let mut conflicts = Vec::new();
    if let Some(repo) = existing {
        if !repo.latest_checkpoint.is_empty()
            && repo.latest_checkpoint != incoming.checkpoint_id
        {
            conflicts.push(format!(
                "checkpoint divergence: local={} incoming={}",
                repo.latest_checkpoint, incoming.checkpoint_id
            ));
        }
    }
    let action = if conflicts.is_empty() {
        "fast-forward"
    } else {
        "delayed-merge"
    };
    Ok(ReconciliationReport {
        action: action.into(),
        conflicts,
        merged_checkpoint: incoming.checkpoint_id.clone(),
    })
}

pub fn validate_reconciliation(manifest_path: &std::path::Path) -> Result<ReconciliationReport> {
    let manifest = read_manifest(manifest_path)?;
    crate::verify_manifest(manifest_path)?;
    Ok(ReconciliationReport {
        action: "validated".into(),
        conflicts: Vec::new(),
        merged_checkpoint: manifest.checkpoint_id,
    })
}

pub fn record_reconciliation(vault: &Vault, repo_id: &str, report: &ReconciliationReport) -> Result<()> {
    gitp2p_core::write_kv(
        &vault.path.join("replication").join(format!("recon-{repo_id}")),
        &[
            ("repo_id", repo_id),
            ("action", &report.action),
            ("merged_checkpoint", &report.merged_checkpoint),
            ("conflicts", &report.conflicts.join(",")),
            ("updated_at", &timestamp()),
        ],
    )
}

pub fn reconcile_repo(app: &gitp2p_core::App, repo_ref: &str) -> Result<ReconciliationReport> {
    let repo = app.find_repo(Some(repo_ref))?;
    let head = gitp2p_core::git::git_output(["rev-parse", "HEAD"], Some(&repo.path))?;
    let head = head.trim();
    let mut conflicts = Vec::new();
    if !repo.latest_checkpoint.is_empty() {
        if let Ok((_, _, checkpoint)) = app.find_checkpoint(&repo.latest_checkpoint) {
            if checkpoint.commit != head {
                conflicts.push(format!(
                    "checkpoint divergence: local={} head={}",
                    checkpoint.commit, head
                ));
            }
        }
    }
    let action = if conflicts.is_empty() { "in-sync" } else { "reconcile-needed" };
    let report = ReconciliationReport {
        action: action.into(),
        conflicts,
        merged_checkpoint: repo.latest_checkpoint.clone(),
    };
    let vault = app.find_vault(&repo.vault_id)?;
    record_reconciliation(&vault, &repo.id, &report)?;
    Ok(report)
}

pub fn list_reconciliation_history(
    app: &gitp2p_core::App,
    repo_ref: Option<&str>,
) -> Result<Vec<(String, String, String, String)>> {
    let mut history = Vec::new();
    for vault in app.all_vaults()? {
        let dir = vault.path.join("replication");
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let file_name = entry.file_name().into_string().unwrap_or_default();
            if !file_name.starts_with("recon-") {
                continue;
            }
            let map = gitp2p_core::read_kv(&entry.path())?;
            let repo_id = gitp2p_core::optional_field(&map, "repo_id");
            if repo_ref.map(|r| {
                app.find_repo(Some(r))
                    .map(|repo| repo.id == repo_id)
                    .unwrap_or(false)
            }).unwrap_or(true) {
                history.push((
                    repo_id,
                    gitp2p_core::optional_field(&map, "action"),
                    gitp2p_core::optional_field(&map, "merged_checkpoint"),
                    gitp2p_core::optional_field(&map, "updated_at"),
                ));
            }
        }
    }
    history.sort_by(|a, b| b.3.cmp(&a.3));
    Ok(history)
}
