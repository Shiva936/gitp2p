use gitp2p_core::identity::team_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, AppError, Result, Team};
use crate::{ensure_enterprise_layout, find_organization, teams_dir};
use gitp2p_core::trust::sign_bytes;
use gitp2p_core::App;

pub fn create_team(app: &App, org_ref: &str, name: &str) -> Result<Team> {
    ensure_enterprise_layout(&app.home)?;
    let org = find_organization(app, org_ref)?;
    let identity = app.ensure_identity()?;
    let id = team_id(&org.id, name);
    if teams_dir(&app.home).join(&id).exists() {
        return Err(AppError::new(format!("team '{name}' already exists")));
    }
    let mut team = Team {
        id,
        org_id: org.id.clone(),
        name: name.to_string(),
        members: identity.peer_id.clone(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = format!("team:{}:{}:{}", team.id, team.org_id, team.name);
    team.signature = sign_bytes(&identity, payload.as_bytes())?;
    team.signed_by = identity.peer_id.clone();
    team.signed_at = gitp2p_core::util::timestamp();
    write_kv(
        &teams_dir(&app.home).join(&team.id),
        &[
            ("id", &team.id),
            ("org_id", &team.org_id),
            ("name", &team.name),
            ("members", &team.members),
            ("created_at", &team.created_at),
            ("signature", &team.signature),
            ("signed_by", &team.signed_by),
            ("signed_at", &team.signed_at),
        ],
    )?;
    Ok(team)
}

pub fn list_teams(app: &App, org_ref: Option<&str>) -> Result<Vec<Team>> {
    ensure_enterprise_layout(&app.home)?;
    let dir = teams_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let org_id = org_ref.map(|r| find_organization(app, r).map(|o| o.id)).transpose()?;
    let mut teams = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            let team = Team {
                id: field(&map, "id")?,
                org_id: field(&map, "org_id")?,
                name: field(&map, "name")?,
                members: optional_field(&map, "members"),
                created_at: field(&map, "created_at")?,
                signature: optional_field(&map, "signature"),
                signed_by: optional_field(&map, "signed_by"),
                signed_at: optional_field(&map, "signed_at"),
            };
            if org_id.as_ref().map(|id| &team.org_id == id).unwrap_or(true) {
                teams.push(team);
            }
        }
    }
    Ok(teams)
}

pub fn find_team(app: &App, reference: &str) -> Result<Team> {
    list_teams(app, None)?
        .into_iter()
        .find(|t| t.id == reference || t.name == reference)
        .ok_or_else(|| AppError::new(format!("team '{reference}' not found")))
}

pub fn inspect_team(app: &App, reference: &str) -> Result<Team> {
    find_team(app, reference)
}

pub fn assign_member(app: &App, team_ref: &str, peer_id: &str) -> Result<Team> {
    let mut team = find_team(app, team_ref)?;
    if !team.members.contains(peer_id) {
        if !team.members.is_empty() {
            team.members.push(',');
        }
        team.members.push_str(peer_id);
    }
    let identity = app.ensure_identity()?;
    let payload = format!("team:{}:{}:{}", team.id, team.org_id, team.name);
    team.signature = sign_bytes(&identity, payload.as_bytes())?;
    team.signed_by = identity.peer_id.clone();
    team.signed_at = gitp2p_core::util::timestamp();
    write_kv(
        &teams_dir(&app.home).join(&team.id),
        &[
            ("id", &team.id),
            ("org_id", &team.org_id),
            ("name", &team.name),
            ("members", &team.members),
            ("created_at", &team.created_at),
            ("signature", &team.signature),
            ("signed_by", &team.signed_by),
            ("signed_at", &team.signed_at),
        ],
    )?;
    Ok(team)
}
