use gitp2p_manifest::{read_manifest, FederationManifest};
use gitp2p_metadata::{Repo, Result, Vault};
use gitp2p_metadata::util::timestamp;

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
    gitp2p_manifest::verify_manifest(manifest_path)?;
    Ok(ReconciliationReport {
        action: "validated".into(),
        conflicts: Vec::new(),
        merged_checkpoint: manifest.checkpoint_id,
    })
}

pub fn record_reconciliation(vault: &Vault, repo_id: &str, report: &ReconciliationReport) -> Result<()> {
    gitp2p_metadata::write_kv(
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
