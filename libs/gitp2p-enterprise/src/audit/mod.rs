use gitp2p_core::identity::audit_event_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, AuditEvent, Result};
use crate::{audit_dir, ensure_enterprise_layout};
use gitp2p_core::App;

pub fn record_event(
    app: &App,
    org_id: &str,
    source: &str,
    action: &str,
    actor: &str,
    details: &str,
) -> Result<AuditEvent> {
    ensure_enterprise_layout(&app.home)?;
    let event = AuditEvent {
        id: audit_event_id(),
        org_id: org_id.to_string(),
        source: source.to_string(),
        action: action.to_string(),
        actor: actor.to_string(),
        details: details.to_string(),
        created_at: gitp2p_core::util::timestamp(),
    };
    write_kv(
        &audit_dir(&app.home).join(&event.id),
        &[
            ("id", &event.id),
            ("org_id", &event.org_id),
            ("source", &event.source),
            ("action", &event.action),
            ("actor", &event.actor),
            ("details", &event.details),
            ("created_at", &event.created_at),
        ],
    )?;
    Ok(event)
}

pub fn search_audit(
    app: &App,
    org_id: Option<&str>,
    source: Option<&str>,
    action: Option<&str>,
) -> Result<Vec<AuditEvent>> {
    ensure_enterprise_layout(&app.home)?;
    let dir = audit_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut events = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            let event = AuditEvent {
                id: field(&map, "id")?,
                org_id: field(&map, "org_id")?,
                source: field(&map, "source")?,
                action: field(&map, "action")?,
                actor: field(&map, "actor")?,
                details: optional_field(&map, "details"),
                created_at: field(&map, "created_at")?,
            };
            if org_id.map(|o| event.org_id == o).unwrap_or(true)
                && source.map(|s| event.source == s).unwrap_or(true)
                && action.map(|a| event.action == a).unwrap_or(true)
            {
                events.push(event);
            }
        }
    }
    events.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(events)
}

pub fn export_audit(app: &App, org_id: Option<&str>) -> Result<String> {
    let events = search_audit(app, org_id, None, None)?;
    let mut out = String::from("audit export\n");
    for event in events {
        out.push_str(&format!(
            "{} {} {} {} {} {}\n",
            event.created_at, event.org_id, event.source, event.action, event.actor, event.details
        ));
    }
    Ok(out)
}

pub fn inspect_audit(app: &App, event_id: &str) -> Result<AuditEvent> {
    let path = audit_dir(&app.home).join(event_id);
    let map = read_kv(&path)?;
    Ok(AuditEvent {
        id: field(&map, "id")?,
        org_id: field(&map, "org_id")?,
        source: field(&map, "source")?,
        action: field(&map, "action")?,
        actor: field(&map, "actor")?,
        details: optional_field(&map, "details"),
        created_at: field(&map, "created_at")?,
    })
}
