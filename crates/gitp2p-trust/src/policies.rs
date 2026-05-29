use std::path::{Path, PathBuf};

use gitp2p_metadata::{optional_field, read_kv, write_kv, Policy, Result, Vault};
use gitp2p_metadata::util::contains_csv;

pub fn default_policy() -> Policy {
    Policy {
        require_approval_for_zones: "protected,experimental,ai-generated".into(),
        ..Default::default()
    }
}

pub fn load_policy(path: &Path) -> Result<Policy> {
    if !path.exists() {
        return Ok(default_policy());
    }
    let map = read_kv(path)?;
    Ok(Policy {
        require_approval_for_zones: optional_field(&map, "require_approval_for_zones"),
        allowed_peer_ids: optional_field(&map, "allowed_peer_ids"),
        blocked_peer_ids: optional_field(&map, "blocked_peer_ids"),
        retention_max_checkpoints: optional_field(&map, "retention_max_checkpoints"),
        retention_max_age_days: optional_field(&map, "retention_max_age_days"),
        protected_checkpoint_ids: optional_field(&map, "protected_checkpoint_ids"),
    })
}

pub fn write_policy(path: &Path, policy: &Policy) -> Result<()> {
    write_kv(path, &policy.fields())
}

pub fn vault_policy_path(vault: &Vault) -> PathBuf {
    vault.path.join("policies").join("default.policy")
}

pub fn repo_policy_path(vault: &Vault, repo_id: &str) -> PathBuf {
    vault
        .path
        .join("policies")
        .join("repos")
        .join(format!("{repo_id}.policy"))
}

pub fn merged_policy(vault: &Vault, repo_id: Option<&str>) -> Result<Policy> {
    let mut policy = load_policy(&vault_policy_path(vault))?;
    if let Some(repo_id) = repo_id {
        let repo_path = repo_policy_path(vault, repo_id);
        if repo_path.exists() {
            let override_policy = load_policy(&repo_path)?;
            merge_policy(&mut policy, &override_policy);
        }
    }
    if policy.require_approval_for_zones.is_empty() {
        policy.require_approval_for_zones = default_policy().require_approval_for_zones;
    }
    Ok(policy)
}

fn merge_policy(base: &mut Policy, override_policy: &Policy) {
    for (target, value) in [
        (
            &mut base.require_approval_for_zones,
            &override_policy.require_approval_for_zones,
        ),
        (
            &mut base.allowed_peer_ids,
            &override_policy.allowed_peer_ids,
        ),
        (
            &mut base.blocked_peer_ids,
            &override_policy.blocked_peer_ids,
        ),
        (
            &mut base.retention_max_checkpoints,
            &override_policy.retention_max_checkpoints,
        ),
        (
            &mut base.retention_max_age_days,
            &override_policy.retention_max_age_days,
        ),
        (
            &mut base.protected_checkpoint_ids,
            &override_policy.protected_checkpoint_ids,
        ),
    ] {
        if !value.is_empty() {
            *target = value.clone();
        }
    }
}

pub fn enforce_peer_policy(policy: &Policy, peer_id: &str) -> Result<()> {
    if contains_csv(&policy.blocked_peer_ids, peer_id) {
        return Err(gitp2p_metadata::AppError::new(format!(
            "peer '{peer_id}' is blocked by vault policy"
        )));
    }
    if !policy.allowed_peer_ids.is_empty() && !contains_csv(&policy.allowed_peer_ids, peer_id) {
        return Err(gitp2p_metadata::AppError::new(format!(
            "peer '{peer_id}' is not in allowed_peer_ids policy"
        )));
    }
    Ok(())
}

pub fn zone_requires_policy_approval(policy: &Policy, zone: &str) -> bool {
    contains_csv(&policy.require_approval_for_zones, zone)
}

pub fn set_policy_field(
    vault: &Vault,
    repo_id: Option<&str>,
    key: &str,
    value: &str,
) -> Result<()> {
    let path = match repo_id {
        Some(repo_id) => repo_policy_path(vault, repo_id),
        None => vault_policy_path(vault),
    };
    let mut policy = if path.exists() {
        load_policy(&path)?
    } else {
        default_policy()
    };
    match key {
        "require_approval_for_zones" => policy.require_approval_for_zones = value.to_string(),
        "allowed_peer_ids" => policy.allowed_peer_ids = value.to_string(),
        "blocked_peer_ids" => policy.blocked_peer_ids = value.to_string(),
        "retention_max_checkpoints" => policy.retention_max_checkpoints = value.to_string(),
        "retention_max_age_days" => policy.retention_max_age_days = value.to_string(),
        "protected_checkpoint_ids" => policy.protected_checkpoint_ids = value.to_string(),
        other => {
            return Err(gitp2p_metadata::AppError::new(format!(
                "unknown policy field '{other}'"
            )));
        }
    }
    write_policy(&path, &policy)
}

pub fn show_policy(vault: &Vault, repo_id: Option<&str>) -> Result<Policy> {
    merged_policy(vault, repo_id)
}
