mod layout;

pub use layout::*;

use gitp2p_core::identity::runtime_policy_id;
use gitp2p_core::{
    field, optional_field, read_kv, write_kv, AppError, Result, RuntimePolicy,
};
use gitp2p_core::trust::{sign_bytes, verify_bytes};
use gitp2p_core::App;

const VALID_KINDS: &[&str] = &["sync", "replica", "checkpoint", "recovery", "trust"];

pub fn policy_payload(policy: &RuntimePolicy) -> String {
    format!(
        "policy:{}:{}:{}:{}:{}",
        policy.id, policy.name, policy.kind, policy.scope_vault, policy.fields
    )
}

pub fn read_policy(path: &std::path::Path) -> Result<RuntimePolicy> {
    let map = read_kv(path)?;
    Ok(RuntimePolicy {
        id: field(&map, "id")?,
        name: field(&map, "name")?,
        kind: field(&map, "kind")?,
        scope_vault: optional_field(&map, "scope_vault"),
        scope_repo: optional_field(&map, "scope_repo"),
        scope_domain: optional_field(&map, "scope_domain"),
        fields: optional_field(&map, "fields"),
        active: optional_field(&map, "active"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_policy(home: &std::path::Path, policy: &RuntimePolicy) -> Result<()> {
    write_kv(
        &policies_dir(home).join(&policy.id),
        &[
            ("id", &policy.id),
            ("name", &policy.name),
            ("kind", &policy.kind),
            ("scope_vault", &policy.scope_vault),
            ("scope_repo", &policy.scope_repo),
            ("scope_domain", &policy.scope_domain),
            ("fields", &policy.fields),
            ("active", &policy.active),
            ("created_at", &policy.created_at),
            ("signature", &policy.signature),
            ("signed_by", &policy.signed_by),
            ("signed_at", &policy.signed_at),
        ],
    )
}

pub fn sign_policy(identity: &gitp2p_core::Identity, policy: &mut RuntimePolicy) -> Result<()> {
    let payload = policy_payload(policy);
    policy.signature = sign_bytes(identity, payload.as_bytes())?;
    policy.signed_by = identity.peer_id.clone();
    policy.signed_at = gitp2p_core::util::timestamp();
    Ok(())
}

pub fn verify_policy(policy: &RuntimePolicy, public_key: &str) -> Result<()> {
    if policy.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(public_key, policy_payload(policy).as_bytes(), &policy.signature)
}

pub fn validate_policy(policy: &RuntimePolicy) -> Result<()> {
    if !VALID_KINDS.contains(&policy.kind.as_str()) {
        return Err(AppError::new(format!(
            "invalid policy kind '{}'",
            policy.kind
        )));
    }
    Ok(())
}

pub fn create_policy(
    app: &App,
    name: &str,
    kind: &str,
    scope_vault: &str,
    fields: &str,
) -> Result<RuntimePolicy> {
    ensure_runtime_layout(&app.home)?;
    if !VALID_KINDS.contains(&kind) {
        return Err(AppError::new(format!("invalid policy kind '{kind}'")));
    }
    let identity = app.ensure_identity()?;
    let id = runtime_policy_id(name);
    if policies_dir(&app.home).join(&id).exists() {
        return Err(AppError::new(format!("policy '{name}' already exists")));
    }
    let mut policy = RuntimePolicy {
        id,
        name: name.to_string(),
        kind: kind.to_string(),
        scope_vault: scope_vault.to_string(),
        scope_repo: String::new(),
        scope_domain: String::new(),
        fields: fields.to_string(),
        active: "true".into(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    validate_policy(&policy)?;
    sign_policy(&identity, &mut policy)?;
    write_policy(&app.home, &policy)?;
    Ok(policy)
}

pub fn list_policies(app: &App) -> Result<Vec<RuntimePolicy>> {
    ensure_runtime_layout(&app.home)?;
    let dir = policies_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut policies = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            policies.push(read_policy(&entry.path())?);
        }
    }
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(policies)
}

pub fn find_policy(app: &App, reference: &str) -> Result<RuntimePolicy> {
    list_policies(app)?
        .into_iter()
        .find(|p| p.id == reference || p.name == reference)
        .ok_or_else(|| AppError::new(format!("policy '{reference}' not found")))
}

pub fn update_policy(
    app: &App,
    reference: &str,
    fields: Option<&str>,
    active: Option<&str>,
) -> Result<RuntimePolicy> {
    let mut policy = find_policy(app, reference)?;
    if let Some(f) = fields {
        policy.fields = f.to_string();
    }
    if let Some(a) = active {
        policy.active = a.to_string();
    }
    validate_policy(&policy)?;
    let identity = app.ensure_identity()?;
    sign_policy(&identity, &mut policy)?;
    write_policy(&app.home, &policy)?;
    Ok(policy)
}

pub fn delete_policy(app: &App, reference: &str) -> Result<RuntimePolicy> {
    let policy = find_policy(app, reference)?;
    std::fs::remove_file(policies_dir(&app.home).join(&policy.id))?;
    Ok(policy)
}

pub fn evaluate_policy(app: &App, vault: &str, repo: Option<&str>) -> Result<Vec<RuntimePolicy>> {
    Ok(list_policies(app)?
        .into_iter()
        .filter(|p| p.active == "true")
        .filter(|p| p.scope_vault.is_empty() || p.scope_vault == vault)
        .filter(|p| {
            repo.map(|r| p.scope_repo.is_empty() || p.scope_repo == r)
                .unwrap_or(true)
        })
        .collect())
}

pub fn policy_field(policy: &RuntimePolicy, key: &str) -> Option<String> {
    policy.fields.split(',').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k.trim() == key {
            Some(v.trim().to_string())
        } else {
            None
        }
    })
}

pub fn policy_field_u32(policy: &RuntimePolicy, key: &str, default: u32) -> u32 {
    policy_field(policy, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
