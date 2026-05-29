mod layout;

pub use layout::*;

use gitp2p_core::identity::organization_id;
use gitp2p_core::{
    field, optional_field, read_kv, write_kv, AppError, Organization, Result,
};
use gitp2p_core::trust::{sign_bytes, verify_bytes};
use gitp2p_core::App;

pub fn org_payload(org: &Organization) -> String {
    format!("org:{}:{}:{}", org.id, org.name, org.owner_peer_id)
}

pub fn read_organization(path: &std::path::Path) -> Result<Organization> {
    let map = read_kv(path)?;
    Ok(Organization {
        id: field(&map, "id")?,
        name: field(&map, "name")?,
        owner_peer_id: field(&map, "owner_peer_id")?,
        members: optional_field(&map, "members"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_organization(home: &std::path::Path, org: &Organization) -> Result<()> {
    write_kv(
        &organizations_dir(home).join(&org.id),
        &[
            ("id", &org.id),
            ("name", &org.name),
            ("owner_peer_id", &org.owner_peer_id),
            ("members", &org.members),
            ("created_at", &org.created_at),
            ("signature", &org.signature),
            ("signed_by", &org.signed_by),
            ("signed_at", &org.signed_at),
        ],
    )
}

pub fn create_organization(app: &App, name: &str) -> Result<Organization> {
    ensure_enterprise_layout(&app.home)?;
    let identity = app.ensure_identity()?;
    let id = organization_id(name);
    if organizations_dir(&app.home).join(&id).exists() {
        return Err(AppError::new(format!("organization '{name}' already exists")));
    }
    let mut org = Organization {
        id,
        name: name.to_string(),
        owner_peer_id: identity.peer_id.clone(),
        members: identity.peer_id.clone(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = org_payload(&org);
    org.signature = sign_bytes(&identity, payload.as_bytes())?;
    org.signed_by = identity.peer_id.clone();
    org.signed_at = gitp2p_core::util::timestamp();
    write_organization(&app.home, &org)?;
    Ok(org)
}

pub fn list_organizations(app: &App) -> Result<Vec<Organization>> {
    ensure_enterprise_layout(&app.home)?;
    let dir = organizations_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut orgs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            orgs.push(read_organization(&entry.path())?);
        }
    }
    orgs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(orgs)
}

pub fn find_organization(app: &App, reference: &str) -> Result<Organization> {
    list_organizations(app)?
        .into_iter()
        .find(|o| o.id == reference || o.name == reference)
        .ok_or_else(|| AppError::new(format!("organization '{reference}' not found")))
}

pub fn inspect_organization(app: &App, reference: &str) -> Result<Organization> {
    find_organization(app, reference)
}

pub fn update_organization(app: &App, reference: &str, name: Option<&str>) -> Result<Organization> {
    let mut org = find_organization(app, reference)?;
    if let Some(n) = name {
        org.name = n.to_string();
    }
    let identity = app.ensure_identity()?;
    let payload = org_payload(&org);
    org.signature = sign_bytes(&identity, payload.as_bytes())?;
    org.signed_by = identity.peer_id.clone();
    org.signed_at = gitp2p_core::util::timestamp();
    write_organization(&app.home, &org)?;
    Ok(org)
}

pub fn add_member(app: &App, reference: &str, peer_id: &str) -> Result<Organization> {
    let mut org = find_organization(app, reference)?;
    if !org.members.contains(peer_id) {
        if !org.members.is_empty() {
            org.members.push(',');
        }
        org.members.push_str(peer_id);
    }
    let identity = app.ensure_identity()?;
    let payload = org_payload(&org);
    org.signature = sign_bytes(&identity, payload.as_bytes())?;
    org.signed_by = identity.peer_id.clone();
    org.signed_at = gitp2p_core::util::timestamp();
    write_organization(&app.home, &org)?;
    Ok(org)
}

pub fn remove_member(app: &App, reference: &str, peer_id: &str) -> Result<Organization> {
    let mut org = find_organization(app, reference)?;
    let members: Vec<_> = org
        .members
        .split(',')
        .filter(|m| !m.is_empty() && *m != peer_id)
        .collect();
    org.members = members.join(",");
    let identity = app.ensure_identity()?;
    let payload = org_payload(&org);
    org.signature = sign_bytes(&identity, payload.as_bytes())?;
    org.signed_by = identity.peer_id.clone();
    org.signed_at = gitp2p_core::util::timestamp();
    write_organization(&app.home, &org)?;
    Ok(org)
}

pub fn verify_organization(org: &Organization, public_key: &str) -> Result<()> {
    if org.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(public_key, org_payload(org).as_bytes(), &org.signature)
}
