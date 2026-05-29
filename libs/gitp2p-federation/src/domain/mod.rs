mod layout;

use gitp2p_core::identity::domain_id;
use gitp2p_core::{
    field, optional_field, read_kv, write_kv, FederationDomain, Identity, Result,
};
use gitp2p_core::util::timestamp;
use gitp2p_core::trust::{sign_bytes, verify_bytes};
use gitp2p_core::App;

pub use layout::*;

pub fn domain_payload(domain: &FederationDomain) -> String {
    format!(
        "domain:{}:{}:{}:{}:{}",
        domain.id, domain.name, domain.owner_peer_id, domain.trust_policy, domain.routing_policy
    )
}

pub fn read_domain(path: &std::path::Path) -> Result<FederationDomain> {
    let map = read_kv(path)?;
    Ok(FederationDomain {
        id: field(&map, "id")?,
        name: field(&map, "name")?,
        owner_peer_id: field(&map, "owner_peer_id")?,
        trust_policy: optional_field(&map, "trust_policy"),
        routing_policy: optional_field(&map, "routing_policy"),
        peering_policy: optional_field(&map, "peering_policy"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_domain(home: &std::path::Path, domain: &FederationDomain) -> Result<()> {
    write_kv(
        &domains_dir(home).join(&domain.id),
        &[
            ("id", &domain.id),
            ("name", &domain.name),
            ("owner_peer_id", &domain.owner_peer_id),
            ("trust_policy", &domain.trust_policy),
            ("routing_policy", &domain.routing_policy),
            ("peering_policy", &domain.peering_policy),
            ("created_at", &domain.created_at),
            ("signature", &domain.signature),
            ("signed_by", &domain.signed_by),
            ("signed_at", &domain.signed_at),
        ],
    )
}

pub fn sign_domain(identity: &Identity, domain: &mut FederationDomain) -> Result<()> {
    let payload = domain_payload(domain);
    domain.signature = sign_bytes(identity, payload.as_bytes())?;
    domain.signed_by = identity.peer_id.clone();
    domain.signed_at = timestamp();
    Ok(())
}

pub fn verify_domain(domain: &FederationDomain, public_key: &str) -> Result<()> {
    if domain.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(public_key, domain_payload(domain).as_bytes(), &domain.signature)
}

pub fn create_domain(app: &App, name: &str) -> Result<FederationDomain> {
    ensure_federation_layout(&app.home)?;
    let identity = app.ensure_identity()?;
    let id = domain_id(name);
    if domains_dir(&app.home).join(&id).exists() {
        return Err(gitp2p_core::AppError::new(format!(
            "domain '{name}' already exists"
        )));
    }
    let mut domain = FederationDomain {
        id,
        name: name.to_string(),
        owner_peer_id: identity.peer_id.clone(),
        trust_policy: "trusted-peers".into(),
        routing_policy: "shortest-path".into(),
        peering_policy: "manual-approve".into(),
        created_at: timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    sign_domain(&identity, &mut domain)?;
    write_domain(&app.home, &domain)?;
    Ok(domain)
}

pub fn list_domains(app: &App) -> Result<Vec<FederationDomain>> {
    let dir = domains_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut domains = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            domains.push(read_domain(&entry.path())?);
        }
    }
    domains.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(domains)
}

pub fn find_domain(app: &App, reference: &str) -> Result<FederationDomain> {
    list_domains(app)?
        .into_iter()
        .find(|d| d.id == reference || d.name == reference)
        .ok_or_else(|| gitp2p_core::AppError::new(format!("domain '{reference}' not found")))
}

pub fn update_domain_policy(
    app: &App,
    reference: &str,
    field_name: &str,
    value: &str,
) -> Result<FederationDomain> {
    let mut domain = find_domain(app, reference)?;
    match field_name {
        "trust_policy" => domain.trust_policy = value.to_string(),
        "routing_policy" => domain.routing_policy = value.to_string(),
        "peering_policy" => domain.peering_policy = value.to_string(),
        other => {
            return Err(gitp2p_core::AppError::new(format!(
                "unknown domain policy field '{other}'"
            )));
        }
    }
    let identity = app.ensure_identity()?;
    sign_domain(&identity, &mut domain)?;
    write_domain(&app.home, &domain)?;
    Ok(domain)
}

pub fn remove_domain(app: &App, reference: &str, confirmed: bool) -> Result<FederationDomain> {
    if !confirmed {
        return Err(gitp2p_core::AppError::new(
            "domain deletion requires --yes",
        ));
    }
    let domain = find_domain(app, reference)?;
    std::fs::remove_file(domains_dir(&app.home).join(&domain.id))?;
    Ok(domain)
}

pub fn local_domain(app: &App) -> Result<Option<FederationDomain>> {
    Ok(list_domains(app)?.into_iter().next())
}

pub fn ensure_local_domain(app: &App) -> Result<FederationDomain> {
    if let Some(domain) = local_domain(app)? {
        return Ok(domain);
    }
    create_domain(app, "local")
}
