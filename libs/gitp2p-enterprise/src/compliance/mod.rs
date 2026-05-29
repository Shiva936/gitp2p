use crate::search_audit;
use gitp2p_core::identity::compliance_report_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, ComplianceReport, Result};
use crate::{compliance_dir, ensure_enterprise_layout, find_organization};
use crate::list_roles;
use gitp2p_runtime::policy::list_policies;
use gitp2p_core::App;

pub fn evaluate_compliance(app: &App, org_ref: &str) -> Result<ComplianceReport> {
    ensure_enterprise_layout(&app.home)?;
    let org = find_organization(app, org_ref)?;
    let mut findings: Vec<String> = Vec::new();

    let roles = list_roles(app, org_ref)?;
    if roles.is_empty() {
        findings.push("no role assignments defined".into());
    }

    let policies = list_policies(app)?;
    let active = policies.iter().filter(|p| p.active == "true").count();
    if active == 0 {
        findings.push("no active runtime policies".into());
    }

    let audit_events = search_audit(app, Some(&org.id), None, None)?;
    if audit_events.is_empty() {
        findings.push("no audit events recorded".into());
    }

    let status = if findings.is_empty() {
        "compliant"
    } else {
        "non-compliant"
    };

    let report = ComplianceReport {
        id: compliance_report_id(&org.id),
        org_id: org.id.clone(),
        status: status.into(),
        findings: findings.join(";"),
        created_at: gitp2p_core::util::timestamp(),
    };

    write_kv(
        &compliance_dir(&app.home).join(&report.id),
        &[
            ("id", &report.id),
            ("org_id", &report.org_id),
            ("status", &report.status),
            ("findings", &report.findings),
            ("created_at", &report.created_at),
        ],
    )?;

    Ok(report)
}

pub fn generate_report(app: &App, org_ref: &str) -> Result<String> {
    let report = evaluate_compliance(app, org_ref)?;
    Ok(format!(
        "compliance report {}\norg: {}\nstatus: {}\nfindings: {}",
        report.id, report.org_id, report.status, report.findings
    ))
}

pub fn inspect_compliance(app: &App, org_ref: &str) -> Result<ComplianceReport> {
    evaluate_compliance(app, org_ref)
}

pub fn latest_compliance(app: &App, org_ref: &str) -> Result<Option<ComplianceReport>> {
    let org = find_organization(app, org_ref)?;
    let dir = compliance_dir(&app.home);
    if !dir.exists() {
        return Ok(None);
    }
    let mut reports = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            reports.push(ComplianceReport {
                id: field(&map, "id")?,
                org_id: field(&map, "org_id")?,
                status: field(&map, "status")?,
                findings: optional_field(&map, "findings"),
                created_at: field(&map, "created_at")?,
            });
        }
    }
    reports.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(reports.into_iter().find(|r| r.org_id == org.id))
}
