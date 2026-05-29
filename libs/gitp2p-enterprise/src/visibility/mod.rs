use crate::search_audit;
use crate::latest_compliance;
use gitp2p_runtime::list_decisions;
use crate::org_trust::list_org_trust;
use crate::list_proposals;
use gitp2p_runtime::{calculate_health, latest_health};
use gitp2p_core::Result;
use crate::find_organization;
use gitp2p_core::App;

pub fn collect_status(app: &App, org_ref: &str) -> Result<String> {
    let org = find_organization(app, org_ref)?;
    let mut out = format!("organization: {} ({})\n", org.name, org.id);

    let vaults = app.all_vaults()?;
    if let Some(vault) = vaults.first() {
        if let Ok(report) = calculate_health(app, &vault.name) {
            out.push_str(&format!(
                "health: sync={} replica={} recovery={} trust={} topology={}\n",
                report.sync_score,
                report.replica_score,
                report.recovery_score,
                report.trust_score,
                report.topology_score
            ));
        } else if let Some(report) = latest_health(app, &vault.name)? {
            out.push_str(&format!(
                "health (cached): sync={} replica={} recovery={}\n",
                report.sync_score, report.replica_score, report.recovery_score
            ));
        }
    }

    let decisions = list_decisions(app)?;
    out.push_str(&format!("recent decisions: {}\n", decisions.len()));

    let proposals = list_proposals(app, Some(org_ref))?;
    let pending = proposals.iter().filter(|p| p.state == "proposed").count();
    out.push_str(&format!("governance: {} proposals ({} pending)\n", proposals.len(), pending));

    let trusts = list_org_trust(app, org_ref)?;
    out.push_str(&format!("org trust relationships: {}\n", trusts.len()));

    let audit_count = search_audit(app, Some(&org.id), None, None)?.len();
    out.push_str(&format!("audit events: {}\n", audit_count));

    if let Some(comp) = latest_compliance(app, org_ref)? {
        out.push_str(&format!("compliance: {}\n", comp.status));
    }

    Ok(out)
}

pub fn generate_report(app: &App, org_ref: &str) -> Result<String> {
    let mut report = String::from("=== visibility report ===\n");
    report.push_str(&collect_status(app, org_ref)?);
    Ok(report)
}

pub fn inspect_visibility(app: &App, org_ref: &str) -> Result<String> {
    collect_status(app, org_ref)
}
