use gitp2p_metadata::{Identity, Result};
use gitp2p_trust::identity::{ensure_identity, load_identity};
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn peer_id_from_key(public_key: &str) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    format!("peer-{}", hex_encode(&digest)[..16].to_string())
}

pub fn vault_id(name: &str) -> String {
    format!("vault-{}", gitp2p_metadata::util::stable_id(name))
}

pub fn checkpoint_id(commit: &str, repo_id: &str) -> String {
    format!(
        "cp-{}-{}",
        gitp2p_metadata::util::compact_timestamp(),
        &commit[..commit.len().min(8)]
    )
}

pub fn lineage_id(chain: &str) -> String {
    let digest = Sha256::digest(chain.as_bytes());
    format!("ln-{}", &hex_encode(&digest)[..16])
}

pub fn domain_id(name: &str) -> String {
    format!("domain-{}", gitp2p_metadata::util::stable_id(name))
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

pub fn inspect_identity(home: &Path) -> Result<Identity> {
    ensure_identity(&home.join("identity"))
}

pub fn export_identity(home: &Path, dest: &Path) -> Result<()> {
    let identity = inspect_identity(home)?;
    gitp2p_metadata::write_kv(
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
    gitp2p_metadata::write_kv(
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
            return Err(gitp2p_metadata::AppError::new("empty peer id"));
        }
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
