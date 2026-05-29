use crate::{create_domain, find_domain, list_domains, write_domain};
use gitp2p_core::FederationDomain;
use gitp2p_core::identity::{domain_id, inspect_identity};
use gitp2p_core::Result;
use crate::list_peerings;
use gitp2p_core::trust::sign_bytes;
use gitp2p_core::App;

#[derive(Clone, Debug)]
pub struct MigrationReport {
    pub source_domain: String,
    pub target_domain: String,
    pub peer_id: String,
    pub vault_ids: Vec<String>,
    pub continuity_ok: bool,
}

pub fn validate_continuity(app: &App, domain: &FederationDomain) -> Result<bool> {
    let identity = inspect_identity(&app.home)?;
    let peer_ok = domain.owner_peer_id == identity.peer_id || domain.owner_peer_id.is_empty();
    let vaults = app.all_vaults()?;
    Ok(peer_ok && !vaults.is_empty())
}

pub fn migrate_domain(
    app: &App,
    target_name: &str,
    vault_filter: Option<&str>,
) -> Result<MigrationReport> {
    let source = list_domains(app)?
        .into_iter()
        .next()
        .ok_or_else(|| gitp2p_core::AppError::new("no local domain to migrate"))?;
    let target = if find_domain(app, target_name).is_ok() {
        find_domain(app, target_name)?
    } else {
        create_domain(app, target_name)?
    };
    let identity = app.ensure_identity()?;
    let vault_ids: Vec<String> = app
        .all_vaults()?
        .into_iter()
        .filter(|v| vault_filter.is_none_or(|f| v.id == f || v.name == f))
        .map(|v| v.id)
        .collect();

    let mut updated = FederationDomain {
        id: domain_id(&format!("{}-{}", source.name, target.name)),
        name: target.name.clone(),
        owner_peer_id: identity.peer_id.clone(),
        trust_policy: source.trust_policy.clone(),
        routing_policy: source.routing_policy.clone(),
        peering_policy: source.peering_policy.clone(),
        created_at: source.created_at.clone(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = format!(
        "migrate:{}:{}:{}",
        source.id,
        target.id,
        updated.owner_peer_id
    );
    updated.signature = sign_bytes(&identity, payload.as_bytes())?;
    updated.signed_by = identity.peer_id.clone();
    updated.signed_at = gitp2p_core::util::timestamp();
    write_domain(&app.home, &updated)?;

    let continuity_ok = validate_continuity(app, &updated)?;
    let _ = list_peerings(app)?;

    Ok(MigrationReport {
        source_domain: source.id,
        target_domain: updated.id,
        peer_id: identity.peer_id,
        vault_ids,
        continuity_ok,
    })
}
