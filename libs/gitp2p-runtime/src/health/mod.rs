use gitp2p_core::identity::health_report_id;
use gitp2p_core::{HealthReport, Result};
use crate::agents::recovery::evaluate_readiness;
use crate::agents::replica::count_replicas;
use gitp2p_federation::inspect_routes;
use crate::policy::{ensure_runtime_layout, health_dir};
use gitp2p_core::App;

pub fn collect_metrics(app: &App, vault: &str) -> Result<(u32, u32, u32, u32, u32, Vec<String>)> {
    let peers = app.all_peers()?;
    let trusted = peers.iter().filter(|p| p.trust_state == "trusted").count() as u32;
    let sync_score = if trusted > 0 { 100 } else { 30 };

    let replicas = count_replicas(app, vault)?;
    let replica_score = (replicas * 33).min(100);

    let (recovery_score, mut risks) = evaluate_readiness(app, vault)?;

    let trust_score = if peers.is_empty() {
        50
    } else {
        (trusted * 100 / peers.len() as u32).max(10)
    };

    let routes = inspect_routes(app)?;
    let topology_score = if routes.is_empty() { 40 } else { 100 };
    if routes.is_empty() && !peers.is_empty() {
        risks.push("no routes available".into());
    }

    Ok((
        sync_score,
        replica_score,
        recovery_score,
        trust_score,
        topology_score,
        risks,
    ))
}

pub fn calculate_health(app: &App, vault: &str) -> Result<HealthReport> {
    ensure_runtime_layout(&app.home)?;
    let (sync_score, replica_score, recovery_score, trust_score, topology_score, risks) =
        collect_metrics(app, vault)?;

    let report = HealthReport {
        id: health_report_id(vault),
        vault_id: vault.into(),
        sync_score,
        replica_score,
        recovery_score,
        trust_score,
        topology_score,
        risks: risks.join(";"),
        created_at: gitp2p_core::util::timestamp(),
    };

    gitp2p_core::write_kv(
        &health_dir(&app.home).join(&report.id),
        &[
            ("id", &report.id),
            ("vault_id", &report.vault_id),
            ("sync_score", &report.sync_score.to_string()),
            ("replica_score", &report.replica_score.to_string()),
            ("recovery_score", &report.recovery_score.to_string()),
            ("trust_score", &report.trust_score.to_string()),
            ("topology_score", &report.topology_score.to_string()),
            ("risks", &report.risks),
            ("created_at", &report.created_at),
        ],
    )?;

    Ok(report)
}

pub fn latest_health(app: &App, vault: &str) -> Result<Option<HealthReport>> {
    ensure_runtime_layout(&app.home)?;
    let dir = health_dir(&app.home);
    if !dir.exists() {
        return Ok(None);
    }
    let mut reports = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = gitp2p_core::read_kv(&entry.path())?;
            reports.push(HealthReport {
                id: gitp2p_core::field(&map, "id")?,
                vault_id: gitp2p_core::optional_field(&map, "vault_id"),
                sync_score: gitp2p_core::optional_field(&map, "sync_score")
                    .parse()
                    .unwrap_or(0),
                replica_score: gitp2p_core::optional_field(&map, "replica_score")
                    .parse()
                    .unwrap_or(0),
                recovery_score: gitp2p_core::optional_field(&map, "recovery_score")
                    .parse()
                    .unwrap_or(0),
                trust_score: gitp2p_core::optional_field(&map, "trust_score")
                    .parse()
                    .unwrap_or(0),
                topology_score: gitp2p_core::optional_field(&map, "topology_score")
                    .parse()
                    .unwrap_or(0),
                risks: gitp2p_core::optional_field(&map, "risks"),
                created_at: gitp2p_core::field(&map, "created_at")?,
            });
        }
    }
    reports.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(reports.into_iter().find(|r| r.vault_id == vault))
}
