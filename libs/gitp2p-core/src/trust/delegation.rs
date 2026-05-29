use std::path::{Path, PathBuf};

use crate::{
    field, optional_field, read_kv, write_kv, Identity, Result, TrustDelegation,
};
use crate::metadata::util::{create_dir_all, timestamp};
use sha2::{Digest, Sha256};

use crate::trust::identity::{sign_bytes, verify_bytes};

fn delegations_dir(home: &Path) -> PathBuf {
    home.join("federation").join("delegations")
}

fn delegation_id(source: &str, target: &str) -> String {
    let digest = Sha256::digest(format!("{source}:{target}").as_bytes());
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("del-{}", &hex[..16])
}

pub fn delegation_payload(delegation: &TrustDelegation) -> String {
    format!(
        "delegation:{}:{}:{}:{}:{}",
        delegation.source_id,
        delegation.target_id,
        delegation.delegation_type,
        delegation.scope,
        delegation.parent_id
    )
}

pub fn read_delegation(path: &Path) -> Result<TrustDelegation> {
    let map = read_kv(path)?;
    Ok(TrustDelegation {
        id: field(&map, "id")?,
        source_id: field(&map, "source_id")?,
        target_id: field(&map, "target_id")?,
        delegation_type: field(&map, "delegation_type")?,
        scope: optional_field(&map, "scope"),
        parent_id: optional_field(&map, "parent_id"),
        state: optional_field(&map, "state"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_delegation(home: &Path, delegation: &TrustDelegation) -> Result<()> {
    create_dir_all(delegations_dir(home))?;
    write_kv(
        &delegations_dir(home).join(&delegation.id),
        &[
            ("id", &delegation.id),
            ("source_id", &delegation.source_id),
            ("target_id", &delegation.target_id),
            ("delegation_type", &delegation.delegation_type),
            ("scope", &delegation.scope),
            ("parent_id", &delegation.parent_id),
            ("state", &delegation.state),
            ("created_at", &delegation.created_at),
            ("signature", &delegation.signature),
            ("signed_by", &delegation.signed_by),
            ("signed_at", &delegation.signed_at),
        ],
    )
}

pub fn sign_delegation(identity: &Identity, delegation: &mut TrustDelegation) -> Result<()> {
    let payload = delegation_payload(delegation);
    delegation.signature = sign_bytes(identity, payload.as_bytes())?;
    delegation.signed_by = identity.peer_id.clone();
    delegation.signed_at = timestamp();
    Ok(())
}

pub fn create_delegation(
    home: &Path,
    identity: &Identity,
    target: &str,
    delegation_type: &str,
    scope: &str,
    parent_id: Option<&str>,
) -> Result<TrustDelegation> {
    let id = delegation_id(&identity.peer_id, target);
    let mut delegation = TrustDelegation {
        id,
        source_id: identity.peer_id.clone(),
        target_id: target.to_string(),
        delegation_type: delegation_type.to_string(),
        scope: scope.to_string(),
        parent_id: parent_id.unwrap_or("").to_string(),
        state: "active".into(),
        created_at: timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    sign_delegation(identity, &mut delegation)?;
    write_delegation(home, &delegation)?;
    Ok(delegation)
}

pub fn list_delegations(home: &Path) -> Result<Vec<TrustDelegation>> {
    let dir = delegations_dir(home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut delegations = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            delegations.push(read_delegation(&entry.path())?);
        }
    }
    Ok(delegations)
}

pub fn find_delegation(home: &Path, id: &str) -> Result<TrustDelegation> {
    list_delegations(home)?
        .into_iter()
        .find(|d| d.id == id || d.target_id == id)
        .ok_or_else(|| crate::AppError::new(format!("delegation '{id}' not found")))
}

pub fn revoke_delegation(home: &Path, identity: &Identity, id: &str) -> Result<TrustDelegation> {
    let mut delegation = find_delegation(home, id)?;
    delegation.state = "revoked".into();
    sign_delegation(identity, &mut delegation)?;
    write_delegation(home, &delegation)?;
    Ok(delegation)
}

pub fn inspect_delegation_chain(home: &Path, root: Option<&str>) -> Result<Vec<TrustDelegation>> {
    let all = list_delegations(home)?;
    let root_id = root.unwrap_or("");
    if root_id.is_empty() {
        return Ok(all);
    }
    let mut chain = Vec::new();
    let mut current = root_id.to_string();
    for _ in 0..16 {
        let Some(node) = all.iter().find(|d| d.id == current || d.target_id == current) else {
            break;
        };
        chain.push(node.clone());
        if node.parent_id.is_empty() {
            break;
        }
        current = node.parent_id.clone();
    }
    Ok(chain)
}

pub fn validate_delegation_chain(
    _home: &Path,
    identity: &Identity,
    chain: &[TrustDelegation],
) -> Result<()> {
    for delegation in chain {
        if delegation.state == "revoked" {
            return Err(crate::AppError::new(format!(
                "delegation {} is revoked",
                delegation.id
            )));
        }
        verify_bytes(
            &identity.public_key,
            delegation_payload(delegation).as_bytes(),
            &delegation.signature,
        )?;
    }
    for window in chain.windows(2) {
        if !window[1].parent_id.is_empty() && window[1].parent_id != window[0].id {
            return Err(crate::AppError::new(
                "delegation chain parent mismatch",
            ));
        }
    }
    Ok(())
}

pub fn verify_delegation(delegation: &TrustDelegation, public_key: &str) -> Result<()> {
    if delegation.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(
        public_key,
        delegation_payload(delegation).as_bytes(),
        &delegation.signature,
    )
}
