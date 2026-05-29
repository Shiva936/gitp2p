use crate::record_event;
use gitp2p_core::identity::org_trust_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, AppError, OrgTrust, Result};
use crate::{ensure_enterprise_layout, find_organization, org_trust_dir};
use gitp2p_core::trust::{sign_bytes, verify_bytes};
use gitp2p_core::App;

pub fn establish_trust(
    app: &App,
    org_ref: &str,
    remote_org_id: &str,
) -> Result<OrgTrust> {
    ensure_enterprise_layout(&app.home)?;
    let org = find_organization(app, org_ref)?;
    let identity = app.ensure_identity()?;
    let id = org_trust_id(&org.id, remote_org_id);
    if org_trust_dir(&app.home).join(&id).exists() {
        return Err(AppError::new("trust relationship already exists"));
    }
    let mut trust = OrgTrust {
        id,
        org_id: org.id.clone(),
        remote_org_id: remote_org_id.to_string(),
        state: "established".into(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = format!("otrust:{}:{}", trust.org_id, trust.remote_org_id);
    trust.signature = sign_bytes(&identity, payload.as_bytes())?;
    trust.signed_by = identity.peer_id.clone();
    trust.signed_at = gitp2p_core::util::timestamp();
    write_trust(&app.home, &trust)?;
    record_event(
        app,
        &org.id,
        "org-trust",
        "establish",
        &identity.peer_id,
        remote_org_id,
    )?;
    Ok(trust)
}

fn write_trust(home: &std::path::Path, trust: &OrgTrust) -> Result<()> {
    write_kv(
        &org_trust_dir(home).join(&trust.id),
        &[
            ("id", &trust.id),
            ("org_id", &trust.org_id),
            ("remote_org_id", &trust.remote_org_id),
            ("state", &trust.state),
            ("created_at", &trust.created_at),
            ("signature", &trust.signature),
            ("signed_by", &trust.signed_by),
            ("signed_at", &trust.signed_at),
        ],
    )
}

pub fn list_org_trust(app: &App, org_ref: &str) -> Result<Vec<OrgTrust>> {
    let org = find_organization(app, org_ref)?;
    ensure_enterprise_layout(&app.home)?;
    let dir = org_trust_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut trusts = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            let trust = OrgTrust {
                id: field(&map, "id")?,
                org_id: field(&map, "org_id")?,
                remote_org_id: field(&map, "remote_org_id")?,
                state: field(&map, "state")?,
                created_at: field(&map, "created_at")?,
                signature: optional_field(&map, "signature"),
                signed_by: optional_field(&map, "signed_by"),
                signed_at: optional_field(&map, "signed_at"),
            };
            if trust.org_id == org.id {
                trusts.push(trust);
            }
        }
    }
    Ok(trusts)
}

pub fn inspect_trust(app: &App, org_ref: &str, remote_org_id: Option<&str>) -> Result<Vec<OrgTrust>> {
    let trusts = list_org_trust(app, org_ref)?;
    if let Some(remote) = remote_org_id {
        Ok(trusts
            .into_iter()
            .filter(|t| t.remote_org_id == remote)
            .collect())
    } else {
        Ok(trusts)
    }
}

pub fn revoke_trust(app: &App, org_ref: &str, remote_org_id: &str) -> Result<OrgTrust> {
    let org = find_organization(app, org_ref)?;
    let id = org_trust_id(&org.id, remote_org_id);
    let path = org_trust_dir(&app.home).join(&id);
    if !path.exists() {
        return Err(AppError::new(format!("no trust with '{remote_org_id}'")));
    }
    let map = read_kv(&path)?;
    let trust = OrgTrust {
        id: field(&map, "id")?,
        org_id: field(&map, "org_id")?,
        remote_org_id: field(&map, "remote_org_id")?,
        state: "revoked".into(),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    };
    write_trust(&app.home, &trust)?;
    let identity = app.ensure_identity()?;
    record_event(
        app,
        &org.id,
        "org-trust",
        "revoke",
        &identity.peer_id,
        remote_org_id,
    )?;
    Ok(trust)
}

pub fn verify_trust(trust: &OrgTrust, public_key: &str) -> Result<()> {
    if trust.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(
        public_key,
        format!("otrust:{}:{}", trust.org_id, trust.remote_org_id).as_bytes(),
        &trust.signature,
    )
}
