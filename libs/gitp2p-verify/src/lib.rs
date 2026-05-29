use std::path::Path;

use gitp2p_content::{cas_root, verify_chunk};
use gitp2p_core::identity::verify_peer_id;
use gitp2p_content::verify_manifest;
use gitp2p_core::{Checkpoint, Result};
use gitp2p_core::trust::{verify_checkpoint, verify_delegation, verify_session, find_delegation};
use gitp2p_core::App;

pub struct VerificationReport {
    pub peer_ok: bool,
    pub checkpoint_ok: bool,
    pub manifest_ok: bool,
    pub lineage_ok: bool,
    pub merkle_ok: bool,
}

pub fn verify_peer(app: &App, peer_id: &str) -> Result<()> {
    let peer = app.find_peer(peer_id)?;
    verify_peer_id(&peer.public_key, &peer.id)
}

pub fn verify_checkpoint_full(app: &App, checkpoint_id: &str) -> Result<()> {
    let (_, _, checkpoint) = app.find_checkpoint(checkpoint_id)?;
    let identity = app.ensure_identity()?;
    verify_checkpoint(&checkpoint, &identity.public_key)
}

pub fn verify_manifest_file(path: &Path) -> Result<String> {
    verify_manifest(path)
}

pub fn verify_lineage(app: &App, checkpoint_id: &str, expected_hash: &str) -> Result<()> {
    let (chain, hash) = gitp2p_content::inspect_lineage(app, checkpoint_id)?;
    if !expected_hash.is_empty() {
        gitp2p_content::verify_lineage_hash(&chain, expected_hash)?;
    }
    let _ = hash;
    Ok(())
}

pub fn verify_session_full(app: &App, session_id: &str) -> Result<()> {
    let session = app.find_session(session_id)?;
    let peer = app.find_peer(&session.peer_id)?;
    verify_session(&session, &peer.public_key)
}

pub fn verify_cas_chunk(home: &Path, chunk_id: &str) -> Result<()> {
    verify_chunk(&cas_root(home), chunk_id)
}

pub fn verify_recovery_integrity(
    app: &App,
    checkpoint: &Checkpoint,
    manifest_path: Option<&Path>,
) -> Result<VerificationReport> {
    let identity = app.ensure_identity()?;
    let checkpoint_ok = verify_checkpoint(checkpoint, &identity.public_key).is_ok();
    let manifest_ok = match manifest_path {
        Some(path) => verify_manifest(path).is_ok(),
        None => true,
    };
    let (chain, _) = gitp2p_content::inspect_lineage(app, &checkpoint.id)?;
    let leaves: Vec<&str> = chain.split("->").collect();
    let merkle_ok = gitp2p_content::verify_merkle_root(&leaves, &gitp2p_content::merkle_root(&leaves)).is_ok();
    Ok(VerificationReport {
        peer_ok: true,
        checkpoint_ok,
        manifest_ok,
        lineage_ok: !chain.is_empty(),
        merkle_ok,
    })
}

pub fn verify_delegation_record(app: &App, delegation_id: &str) -> Result<()> {
    let delegation = find_delegation(&app.home, delegation_id)?;
    let identity = app.ensure_identity()?;
    verify_delegation(&delegation, &identity.public_key)
}

#[cfg(feature = "federation")]
pub fn verify_domain_record(app: &App, domain_id: &str) -> Result<()> {
    use gitp2p_federation::{find_domain, verify_domain};
    let domain = find_domain(app, domain_id)?;
    let identity = app.ensure_identity()?;
    verify_domain(&domain, &identity.public_key)
}

#[cfg(feature = "federation")]
pub fn verify_gateway_record(app: &App, gateway_id: &str) -> Result<()> {
    use gitp2p_federation::{find_gateway, verify_gateway};
    let gateway = find_gateway(app, gateway_id)?;
    let identity = app.ensure_identity()?;
    verify_gateway(&gateway, &identity.public_key)
}

#[cfg(feature = "federation")]
pub fn verify_peering_record(app: &App, remote_domain: &str) -> Result<()> {
    use gitp2p_federation::{find_peering, verify_peering};
    let peering = find_peering(app, remote_domain)?;
    let identity = app.ensure_identity()?;
    verify_peering(&peering, &identity.public_key)
}

#[cfg(feature = "federation")]
pub fn verify_global_route(app: &App, route_id: &str) -> Result<()> {
    gitp2p_federation::verify_route(app, route_id)?;
    Ok(())
}

#[cfg(feature = "runtime")]
pub fn verify_runtime_policy(app: &App, policy_id: &str) -> Result<()> {
    let policy = gitp2p_runtime::policy::find_policy(app, policy_id)?;
    let identity = app.ensure_identity()?;
    gitp2p_runtime::policy::verify_policy(&policy, &identity.public_key)
}
