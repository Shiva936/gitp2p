use crate::record_event;
use gitp2p_core::identity::admin_delegation_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, AdminDelegation, AppError, Result};
use crate::{administration_dir, ensure_enterprise_layout, find_organization};
use gitp2p_core::trust::sign_bytes;
use gitp2p_core::App;

pub fn delegate_admin(
    app: &App,
    org_ref: &str,
    delegate: &str,
    scope: &str,
) -> Result<AdminDelegation> {
    ensure_enterprise_layout(&app.home)?;
    let org = find_organization(app, org_ref)?;
    let identity = app.ensure_identity()?;
    let id = admin_delegation_id(&org.id, delegate);
    let mut delegation = AdminDelegation {
        id,
        org_id: org.id.clone(),
        delegator: identity.peer_id.clone(),
        delegate: delegate.to_string(),
        scope: scope.to_string(),
        state: "active".into(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = format!(
        "admin:{}:{}:{}",
        delegation.org_id, delegation.delegate, delegation.scope
    );
    delegation.signature = sign_bytes(&identity, payload.as_bytes())?;
    delegation.signed_by = identity.peer_id.clone();
    delegation.signed_at = gitp2p_core::util::timestamp();
    write_kv(
        &administration_dir(&app.home).join(&delegation.id),
        &[
            ("id", &delegation.id),
            ("org_id", &delegation.org_id),
            ("delegator", &delegation.delegator),
            ("delegate", &delegation.delegate),
            ("scope", &delegation.scope),
            ("state", &delegation.state),
            ("created_at", &delegation.created_at),
            ("signature", &delegation.signature),
            ("signed_by", &delegation.signed_by),
            ("signed_at", &delegation.signed_at),
        ],
    )?;
    record_event(
        app,
        &org.id,
        "administration",
        "delegate",
        &identity.peer_id,
        delegate,
    )?;
    Ok(delegation)
}

pub fn revoke_admin(app: &App, org_ref: &str, delegate: &str) -> Result<AdminDelegation> {
    let org = find_organization(app, org_ref)?;
    let id = admin_delegation_id(&org.id, delegate);
    let path = administration_dir(&app.home).join(&id);
    if !path.exists() {
        return Err(AppError::new(format!("no delegation for '{delegate}'")));
    }
    let map = read_kv(&path)?;
    let delegation = AdminDelegation {
        id: field(&map, "id")?,
        org_id: field(&map, "org_id")?,
        delegator: field(&map, "delegator")?,
        delegate: field(&map, "delegate")?,
        scope: field(&map, "scope")?,
        state: "revoked".into(),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    };
    std::fs::remove_file(path)?;
    let identity = app.ensure_identity()?;
    record_event(
        app,
        &org.id,
        "administration",
        "revoke",
        &identity.peer_id,
        delegate,
    )?;
    Ok(delegation)
}

pub fn inspect_admin(app: &App, org_ref: &str) -> Result<Vec<AdminDelegation>> {
    let org = find_organization(app, org_ref)?;
    ensure_enterprise_layout(&app.home)?;
    let dir = administration_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut delegations = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            let d = AdminDelegation {
                id: field(&map, "id")?,
                org_id: field(&map, "org_id")?,
                delegator: field(&map, "delegator")?,
                delegate: field(&map, "delegate")?,
                scope: field(&map, "scope")?,
                state: field(&map, "state")?,
                created_at: field(&map, "created_at")?,
                signature: optional_field(&map, "signature"),
                signed_by: optional_field(&map, "signed_by"),
                signed_at: optional_field(&map, "signed_at"),
            };
            if d.org_id == org.id {
                delegations.push(d);
            }
        }
    }
    Ok(delegations)
}
