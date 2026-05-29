use std::path::{Path, PathBuf};

use crate::{ensure_federation_layout, exchange_dir, gateways_dir, write_exchange_manifest};
use gitp2p_core::identity::gateway_id;
use gitp2p_core::{
    field, optional_field, read_kv, write_kv, Gateway, Identity, Result,
};
use gitp2p_core::util::{create_dir_all, timestamp};
use crate::forward_propagation;
use gitp2p_core::trust::{sign_bytes, verify_bytes};
use gitp2p_core::App;

pub fn gateway_payload(gateway: &Gateway) -> String {
    format!(
        "gateway:{}:{}:{}:{}",
        gateway.id, gateway.domain_id, gateway.listen_addr, gateway.listen_port
    )
}

pub fn gateway_record_path(home: &Path, gateway_id: &str) -> PathBuf {
    gateways_dir(home).join(gateway_id).join("gateway")
}

pub fn read_gateway(home: &Path, gateway_id: &str) -> Result<Gateway> {
    read_gateway_file(&gateway_record_path(home, gateway_id))
}

fn read_gateway_file(path: &Path) -> Result<Gateway> {
    let map = read_kv(path)?;
    Ok(Gateway {
        id: field(&map, "id")?,
        domain_id: field(&map, "domain_id")?,
        listen_addr: field(&map, "listen_addr")?,
        listen_port: optional_field(&map, "listen_port").parse().unwrap_or(8443),
        state: optional_field(&map, "state"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_gateway(home: &Path, gateway: &Gateway) -> Result<()> {
    let dir = gateways_dir(home).join(&gateway.id);
    create_dir_all(&dir)?;
    write_kv(
        &dir.join("gateway"),
        &[
            ("id", &gateway.id),
            ("domain_id", &gateway.domain_id),
            ("listen_addr", &gateway.listen_addr),
            ("listen_port", &gateway.listen_port.to_string()),
            ("state", &gateway.state),
            ("created_at", &gateway.created_at),
            ("signature", &gateway.signature),
            ("signed_by", &gateway.signed_by),
            ("signed_at", &gateway.signed_at),
        ],
    )
}

pub fn sign_gateway(identity: &Identity, gateway: &mut Gateway) -> Result<()> {
    let payload = gateway_payload(gateway);
    gateway.signature = sign_bytes(identity, payload.as_bytes())?;
    gateway.signed_by = identity.peer_id.clone();
    gateway.signed_at = timestamp();
    Ok(())
}

pub fn verify_gateway(gateway: &Gateway, public_key: &str) -> Result<()> {
    if gateway.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(public_key, gateway_payload(gateway).as_bytes(), &gateway.signature)
}

pub fn create_gateway(
    app: &App,
    domain_id: &str,
    listen_addr: &str,
    listen_port: u16,
) -> Result<Gateway> {
    ensure_federation_layout(&app.home)?;
    let identity = app.ensure_identity()?;
    let id = gateway_id(domain_id, listen_addr);
    if gateway_record_path(&app.home, &id).exists() {
        return Err(gitp2p_core::AppError::new(format!(
            "gateway '{id}' already exists"
        )));
    }
    let mut gateway = Gateway {
        id,
        domain_id: domain_id.to_string(),
        listen_addr: listen_addr.to_string(),
        listen_port,
        state: "active".into(),
        created_at: timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    sign_gateway(&identity, &mut gateway)?;
    write_gateway(&app.home, &gateway)?;
    create_dir_all(exchange_dir(&app.home, &gateway.id))?;
    Ok(gateway)
}

pub fn list_gateways(app: &App) -> Result<Vec<Gateway>> {
    let dir = gateways_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut gateways = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            let record = entry.path().join("gateway");
            if record.exists() {
                gateways.push(read_gateway_file(&record)?);
            }
        }
    }
    Ok(gateways)
}

pub fn find_gateway(app: &App, reference: &str) -> Result<Gateway> {
    list_gateways(app)?
        .into_iter()
        .find(|g| g.id == reference || g.domain_id == reference)
        .ok_or_else(|| gitp2p_core::AppError::new(format!("gateway '{reference}' not found")))
}

pub fn exchange_routes(
    app: &App,
    local_gateway_id: &str,
    remote_gateway_id: &str,
    routes: &str,
) -> Result<()> {
    write_exchange_manifest(
        &app.home,
        local_gateway_id,
        "routes",
        remote_gateway_id,
        &[
            ("local_gateway", local_gateway_id),
            ("remote_gateway", remote_gateway_id),
            ("routes", routes),
        ],
    )
}

pub fn exchange_discovery(
    app: &App,
    local_gateway_id: &str,
    remote_gateway_id: &str,
    kind: &str,
    entries: &str,
) -> Result<()> {
    write_exchange_manifest(
        &app.home,
        local_gateway_id,
        &format!("discovery-{kind}"),
        remote_gateway_id,
        &[
            ("local_gateway", local_gateway_id),
            ("remote_gateway", remote_gateway_id),
            ("kind", kind),
            ("entries", entries),
        ],
    )
}

pub fn read_exchanged_routes(home: &Path, gateway_id: &str) -> Result<Vec<(String, String)>> {
    let dir = exchange_dir(home, gateway_id).join("routes");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let map = read_kv(&entry?.path())?;
        out.push((
            optional_field(&map, "remote_gateway"),
            optional_field(&map, "routes"),
        ));
    }
    Ok(out)
}

pub fn sync_forward(
    app: &App,
    session_id: &str,
    next_gateway: &str,
) -> Result<()> {
    forward_propagation(app, session_id, next_gateway)
}
