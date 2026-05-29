use std::path::{Path, PathBuf};

use gitp2p_federation::{ensure_federation_layout, peering_dir};
use gitp2p_gateway::{find_gateway, list_gateways};
use gitp2p_identity::peering_id;
use gitp2p_metadata::{
    field, optional_field, read_kv, write_kv, Identity, Peering, Result,
};
use gitp2p_metadata::util::timestamp;
use gitp2p_trust::{sign_bytes, verify_bytes};
use gitp2p_vault::App;

pub fn peering_payload(peering: &Peering) -> String {
    format!(
        "peering:{}:{}:{}:{}",
        peering.local_domain_id,
        peering.remote_domain_id,
        peering.local_gateway_id,
        peering.remote_gateway_id
    )
}

pub fn peering_path(home: &Path, peering: &Peering) -> PathBuf {
    peering_dir(home).join(&peering.id)
}

pub fn read_peering(path: &Path) -> Result<Peering> {
    let map = read_kv(path)?;
    Ok(Peering {
        id: field(&map, "id")?,
        local_domain_id: field(&map, "local_domain_id")?,
        remote_domain_id: field(&map, "remote_domain_id")?,
        local_gateway_id: field(&map, "local_gateway_id")?,
        remote_gateway_id: field(&map, "remote_gateway_id")?,
        state: optional_field(&map, "state"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_peering(home: &Path, peering: &Peering) -> Result<()> {
    write_kv(
        &peering_path(home, peering),
        &[
            ("id", &peering.id),
            ("local_domain_id", &peering.local_domain_id),
            ("remote_domain_id", &peering.remote_domain_id),
            ("local_gateway_id", &peering.local_gateway_id),
            ("remote_gateway_id", &peering.remote_gateway_id),
            ("state", &peering.state),
            ("created_at", &peering.created_at),
            ("signature", &peering.signature),
            ("signed_by", &peering.signed_by),
            ("signed_at", &peering.signed_at),
        ],
    )
}

pub fn sign_peering(identity: &Identity, peering: &mut Peering) -> Result<()> {
    let payload = peering_payload(peering);
    peering.signature = sign_bytes(identity, payload.as_bytes())?;
    peering.signed_by = identity.peer_id.clone();
    peering.signed_at = timestamp();
    Ok(())
}

pub fn verify_peering(peering: &Peering, public_key: &str) -> Result<()> {
    if peering.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(public_key, peering_payload(peering).as_bytes(), &peering.signature)
}

pub fn connect_domains(
    app: &App,
    local_domain_id: &str,
    remote_domain_id: &str,
    local_gateway_id: Option<&str>,
    remote_gateway_id: Option<&str>,
) -> Result<Peering> {
    ensure_federation_layout(&app.home)?;
    let identity = app.ensure_identity()?;
    let local_gw = match local_gateway_id {
        Some(id) => find_gateway(app, id)?,
        None => list_gateways(app)?
            .into_iter()
            .find(|g| g.domain_id == local_domain_id)
            .ok_or_else(|| gitp2p_metadata::AppError::new("no local gateway found"))?,
    };
    let remote_gw_id = remote_gateway_id.unwrap_or("remote-gateway").to_string();
    let id = peering_id(local_domain_id, remote_domain_id);
    let mut peering = Peering {
        id,
        local_domain_id: local_domain_id.to_string(),
        remote_domain_id: remote_domain_id.to_string(),
        local_gateway_id: local_gw.id.clone(),
        remote_gateway_id: remote_gw_id,
        state: "active".into(),
        created_at: timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    sign_peering(&identity, &mut peering)?;
    write_peering(&app.home, &peering)?;
    Ok(peering)
}

pub fn list_peerings(app: &App) -> Result<Vec<Peering>> {
    let dir = peering_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut peerings = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            peerings.push(read_peering(&entry.path())?);
        }
    }
    Ok(peerings)
}

pub fn find_peering(app: &App, remote_domain: &str) -> Result<Peering> {
    list_peerings(app)?
        .into_iter()
        .find(|p| p.remote_domain_id == remote_domain || p.id == remote_domain)
        .ok_or_else(|| {
            gitp2p_metadata::AppError::new(format!("peering with '{remote_domain}' not found"))
        })
}

pub fn revoke_peering(app: &App, remote_domain: &str) -> Result<Peering> {
    let mut peering = find_peering(app, remote_domain)?;
    peering.state = "revoked".into();
    let identity = app.ensure_identity()?;
    sign_peering(&identity, &mut peering)?;
    write_peering(&app.home, &peering)?;
    Ok(peering)
}

pub fn inspect_peering(app: &App, remote_domain: Option<&str>) -> Result<Vec<Peering>> {
    let peerings = list_peerings(app)?;
    Ok(match remote_domain {
        Some(domain) => peerings
            .into_iter()
            .filter(|p| p.remote_domain_id == domain || p.id == domain)
            .collect(),
        None => peerings,
    })
}
