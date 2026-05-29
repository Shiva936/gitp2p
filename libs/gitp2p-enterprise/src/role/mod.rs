use gitp2p_core::identity::role_assignment_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, AppError, Result, RoleAssignment};
use crate::{ensure_enterprise_layout, find_organization, roles_dir};
use gitp2p_core::trust::sign_bytes;
use gitp2p_core::App;

pub const ROLES: &[&str] = &[
    "owner",
    "administrator",
    "operator",
    "auditor",
    "contributor",
    "observer",
];

pub fn assign_role(app: &App, org_ref: &str, peer_id: &str, role: &str) -> Result<RoleAssignment> {
    ensure_enterprise_layout(&app.home)?;
    let org = find_organization(app, org_ref)?;
    if !ROLES.contains(&role) {
        return Err(AppError::new(format!("invalid role '{role}'")));
    }
    let identity = app.ensure_identity()?;
    let id = role_assignment_id(&org.id, peer_id);
    let mut assignment = RoleAssignment {
        id: id.clone(),
        org_id: org.id.clone(),
        peer_id: peer_id.to_string(),
        role: role.to_string(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = format!("role:{}:{}:{}", assignment.org_id, assignment.peer_id, assignment.role);
    assignment.signature = sign_bytes(&identity, payload.as_bytes())?;
    assignment.signed_by = identity.peer_id.clone();
    assignment.signed_at = gitp2p_core::util::timestamp();
    write_kv(
        &roles_dir(&app.home).join(&assignment.id),
        &[
            ("id", &assignment.id),
            ("org_id", &assignment.org_id),
            ("peer_id", &assignment.peer_id),
            ("role", &assignment.role),
            ("created_at", &assignment.created_at),
            ("signature", &assignment.signature),
            ("signed_by", &assignment.signed_by),
            ("signed_at", &assignment.signed_at),
        ],
    )?;
    Ok(assignment)
}

pub fn revoke_role(app: &App, org_ref: &str, peer_id: &str) -> Result<RoleAssignment> {
    let org = find_organization(app, org_ref)?;
    let id = role_assignment_id(&org.id, peer_id);
    let path = roles_dir(&app.home).join(&id);
    let assignment = if path.exists() {
        let map = read_kv(&path)?;
        let assignment = RoleAssignment {
            id: field(&map, "id")?,
            org_id: field(&map, "org_id")?,
            peer_id: field(&map, "peer_id")?,
            role: field(&map, "role")?,
            created_at: field(&map, "created_at")?,
            signature: optional_field(&map, "signature"),
            signed_by: optional_field(&map, "signed_by"),
            signed_at: optional_field(&map, "signed_at"),
        };
        std::fs::remove_file(path)?;
        assignment
    } else {
        return Err(AppError::new(format!("no role for peer '{peer_id}'")));
    };
    Ok(assignment)
}

pub fn find_role(app: &App, org_ref: &str, peer_id: &str) -> Result<Option<RoleAssignment>> {
    let org = find_organization(app, org_ref)?;
    let id = role_assignment_id(&org.id, peer_id);
    let path = roles_dir(&app.home).join(&id);
    if !path.exists() {
        return Ok(None);
    }
    let map = read_kv(&path)?;
    Ok(Some(RoleAssignment {
        id: field(&map, "id")?,
        org_id: field(&map, "org_id")?,
        peer_id: field(&map, "peer_id")?,
        role: field(&map, "role")?,
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    }))
}

pub fn evaluate_permission(app: &App, org_ref: &str, peer_id: &str, action: &str) -> Result<bool> {
    let org = find_organization(app, org_ref)?;
    if org.owner_peer_id == peer_id {
        return Ok(true);
    }
    let role = find_role(app, org_ref, peer_id)?
        .map(|r| r.role)
        .unwrap_or_else(|| "observer".into());
    Ok(match action {
        "org_admin" | "policy_approve" | "trust_manage" | "automation_run" => {
            matches!(role.as_str(), "owner" | "administrator" | "operator")
        }
        "audit_read" | "visibility_read" => {
            matches!(
                role.as_str(),
                "owner" | "administrator" | "operator" | "auditor" | "observer"
            )
        }
        "compliance_read" => {
            matches!(
                role.as_str(),
                "owner" | "administrator" | "auditor" | "observer"
            )
        }
        _ => false,
    })
}

pub fn require_permission(app: &App, org_ref: &str, peer_id: &str, action: &str) -> Result<()> {
    if evaluate_permission(app, org_ref, peer_id, action)? {
        Ok(())
    } else {
        Err(AppError::new(format!(
            "permission denied: {action} for peer {peer_id}"
        )))
    }
}

pub fn list_roles(app: &App, org_ref: &str) -> Result<Vec<RoleAssignment>> {
    let org = find_organization(app, org_ref)?;
    ensure_enterprise_layout(&app.home)?;
    let dir = roles_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut roles = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            let role = RoleAssignment {
                id: field(&map, "id")?,
                org_id: field(&map, "org_id")?,
                peer_id: field(&map, "peer_id")?,
                role: field(&map, "role")?,
                created_at: field(&map, "created_at")?,
                signature: optional_field(&map, "signature"),
                signed_by: optional_field(&map, "signed_by"),
                signed_at: optional_field(&map, "signed_at"),
            };
            if role.org_id == org.id {
                roles.push(role);
            }
        }
    }
    Ok(roles)
}
