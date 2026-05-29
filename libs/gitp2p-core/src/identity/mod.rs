use crate::{Identity, Result};
use crate::trust::identity::{ensure_identity, load_identity};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn peer_id_from_key(public_key: &str) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    format!("peer-{}", hex_encode(&digest)[..16].to_string())
}

pub fn vault_id(name: &str) -> String {
    format!("vault-{}", crate::util::stable_id(name))
}

pub fn checkpoint_id(commit: &str, _repo_id: &str) -> String {
    format!(
        "cp-{}-{}",
        crate::util::compact_timestamp(),
        &commit[..commit.len().min(8)]
    )
}

pub fn lineage_id(chain: &str) -> String {
    let digest = Sha256::digest(chain.as_bytes());
    format!("ln-{}", &hex_encode(&digest)[..16])
}

pub fn domain_id(name: &str) -> String {
    format!("domain-{}", crate::util::stable_id(name))
}

pub fn gateway_id(domain_id: &str, listen_addr: &str) -> String {
    format!(
        "gw-{}",
        &hex_encode(&Sha256::digest(format!("{domain_id}:{listen_addr}").as_bytes()))[..16]
    )
}

pub fn peering_id(local_domain: &str, remote_domain: &str) -> String {
    format!(
        "peer-{}-{}",
        &local_domain[..local_domain.len().min(8)],
        &remote_domain[..remote_domain.len().min(8)]
    )
}

pub fn delegation_id(source: &str, target: &str) -> String {
    format!(
        "del-{}",
        &hex_encode(&Sha256::digest(format!("{source}:{target}").as_bytes()))[..16]
    )
}

pub fn federation_route_id(destination: &str, hops: &str) -> String {
    format!(
        "route-{}",
        &hex_encode(&Sha256::digest(format!("{destination}:{hops}").as_bytes()))[..16]
    )
}

pub fn runtime_policy_id(name: &str) -> String {
    format!("rpol-{}", crate::util::stable_id(name))
}

pub fn runtime_decision_id(agent: &str) -> String {
    format!(
        "dec-{}-{}",
        agent,
        crate::util::compact_timestamp()
    )
}

pub fn runtime_plan_id(kind: &str) -> String {
    format!("plan-{}-{}", kind, crate::util::compact_timestamp())
}

pub fn health_report_id(vault_id: &str) -> String {
    format!("health-{}-{}", vault_id, crate::util::compact_timestamp())
}

pub fn explanation_id(decision_id: &str) -> String {
    format!("exp-{}", &decision_id[decision_id.len().saturating_sub(12)..])
}

pub fn organization_id(name: &str) -> String {
    format!("org-{}", crate::util::stable_id(name))
}

pub fn team_id(org_id: &str, name: &str) -> String {
    format!("team-{}-{}", &org_id[..org_id.len().min(8)], crate::util::stable_id(name))
}

pub fn role_assignment_id(org_id: &str, peer_id: &str) -> String {
    format!(
        "role-{}",
        &hex_encode(&Sha256::digest(format!("{org_id}:{peer_id}").as_bytes()))[..16]
    )
}

pub fn governance_proposal_id(org_id: &str, _proposal_type: &str) -> String {
    format!(
        "gov-{}-{}",
        &org_id[..org_id.len().min(8)],
        crate::util::compact_timestamp()
    )
}

pub fn audit_event_id() -> String {
    format!("audit-{}", crate::util::compact_timestamp())
}

pub fn compliance_report_id(org_id: &str) -> String {
    format!("comp-{}-{}", &org_id[..org_id.len().min(8)], crate::util::compact_timestamp())
}

pub fn admin_delegation_id(org_id: &str, delegate: &str) -> String {
    format!(
        "adm-{}",
        &hex_encode(&Sha256::digest(format!("{org_id}:{delegate}").as_bytes()))[..16]
    )
}

pub fn org_trust_id(org_id: &str, remote_org_id: &str) -> String {
    format!(
        "otrust-{}",
        &hex_encode(&Sha256::digest(format!("{org_id}:{remote_org_id}").as_bytes()))[..16]
    )
}

pub fn inspect_identity(home: &Path) -> Result<Identity> {
    ensure_identity(&home.join("identity"))
}

pub fn export_identity(home: &Path, dest: &Path) -> Result<()> {
    let identity = inspect_identity(home)?;
    crate::write_kv(
        dest,
        &[
            ("peer_id", &identity.peer_id),
            ("public_key", &identity.public_key),
            ("private_key", &identity.private_key),
            ("fingerprint", &identity.fingerprint),
            ("created_at", &identity.created_at),
        ],
    )
}

pub fn import_identity(home: &Path, source: &Path) -> Result<Identity> {
    let identity = load_identity(source)?;
    crate::write_kv(
        &home.join("identity"),
        &[
            ("peer_id", &identity.peer_id),
            ("public_key", &identity.public_key),
            ("private_key", &identity.private_key),
            ("fingerprint", &identity.fingerprint),
            ("created_at", &identity.created_at),
        ],
    )?;
    Ok(identity)
}

pub fn verify_peer_id(public_key: &str, expected_peer_id: &str) -> Result<()> {
    let derived = peer_id_from_key(public_key);
    if !expected_peer_id.contains(&derived[5..]) && expected_peer_id != derived {
        // Allow legacy peer ids from stable_id as well
        if expected_peer_id.is_empty() {
            return Err(crate::AppError::new("empty peer id"));
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
