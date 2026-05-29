use crate::record_event;
use gitp2p_core::identity::governance_proposal_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, AppError, GovernanceProposal, Result};
use crate::{ensure_enterprise_layout, find_organization, governance_dir};
use gitp2p_runtime::policy::{create_policy, update_policy};
use gitp2p_core::trust::sign_bytes;
use gitp2p_core::App;

pub fn create_proposal(
    app: &App,
    org_ref: &str,
    proposal_type: &str,
    subject_id: &str,
    details: &str,
) -> Result<GovernanceProposal> {
    ensure_enterprise_layout(&app.home)?;
    let org = find_organization(app, org_ref)?;
    let identity = app.ensure_identity()?;
    let id = governance_proposal_id(&org.id, proposal_type);
    let mut proposal = GovernanceProposal {
        id,
        org_id: org.id.clone(),
        proposal_type: proposal_type.to_string(),
        subject_id: subject_id.to_string(),
        state: "proposed".into(),
        proposer: identity.peer_id.clone(),
        reviewer: String::new(),
        details: details.to_string(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    let payload = format!(
        "gov:{}:{}:{}",
        proposal.id, proposal.proposal_type, proposal.subject_id
    );
    proposal.signature = sign_bytes(&identity, payload.as_bytes())?;
    proposal.signed_by = identity.peer_id.clone();
    proposal.signed_at = gitp2p_core::util::timestamp();
    write_proposal(&app.home, &proposal)?;
    record_event(
        app,
        &org.id,
        "governance",
        "propose",
        &identity.peer_id,
        &format!("{}:{}", proposal_type, subject_id),
    )?;
    Ok(proposal)
}

fn write_proposal(home: &std::path::Path, proposal: &GovernanceProposal) -> Result<()> {
    write_kv(
        &governance_dir(home).join(&proposal.id),
        &[
            ("id", &proposal.id),
            ("org_id", &proposal.org_id),
            ("proposal_type", &proposal.proposal_type),
            ("subject_id", &proposal.subject_id),
            ("state", &proposal.state),
            ("proposer", &proposal.proposer),
            ("reviewer", &proposal.reviewer),
            ("details", &proposal.details),
            ("created_at", &proposal.created_at),
            ("signature", &proposal.signature),
            ("signed_by", &proposal.signed_by),
            ("signed_at", &proposal.signed_at),
        ],
    )
}

pub fn read_proposal(path: &std::path::Path) -> Result<GovernanceProposal> {
    let map = read_kv(path)?;
    Ok(GovernanceProposal {
        id: field(&map, "id")?,
        org_id: field(&map, "org_id")?,
        proposal_type: field(&map, "proposal_type")?,
        subject_id: field(&map, "subject_id")?,
        state: field(&map, "state")?,
        proposer: field(&map, "proposer")?,
        reviewer: optional_field(&map, "reviewer"),
        details: optional_field(&map, "details"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn list_proposals(app: &App, org_ref: Option<&str>) -> Result<Vec<GovernanceProposal>> {
    ensure_enterprise_layout(&app.home)?;
    let org_id = org_ref.map(|r| find_organization(app, r).map(|o| o.id)).transpose()?;
    let dir = governance_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut proposals = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let proposal = read_proposal(&entry.path())?;
            if org_id.as_ref().map(|id| &proposal.org_id == id).unwrap_or(true) {
                proposals.push(proposal);
            }
        }
    }
    Ok(proposals)
}

pub fn find_proposal(app: &App, id: &str) -> Result<GovernanceProposal> {
    let path = governance_dir(&app.home).join(id);
    if path.exists() {
        return read_proposal(&path);
    }
    list_proposals(app, None)?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::new(format!("proposal '{id}' not found")))
}

pub fn review_proposal(app: &App, id: &str) -> Result<GovernanceProposal> {
    let mut proposal = find_proposal(app, id)?;
    let identity = app.ensure_identity()?;
    proposal.state = "reviewed".into();
    proposal.reviewer = identity.peer_id.clone();
    let payload = format!(
        "gov:{}:{}:{}",
        proposal.id, proposal.proposal_type, proposal.subject_id
    );
    proposal.signature = sign_bytes(&identity, payload.as_bytes())?;
    proposal.signed_at = gitp2p_core::util::timestamp();
    write_proposal(&app.home, &proposal)?;
    record_event(
        app,
        &proposal.org_id,
        "governance",
        "review",
        &identity.peer_id,
        &proposal.id,
    )?;
    Ok(proposal)
}

pub fn approve_proposal(app: &App, id: &str) -> Result<GovernanceProposal> {
    let mut proposal = find_proposal(app, id)?;
    let identity = app.ensure_identity()?;
    proposal.state = "approved".into();
    proposal.reviewer = identity.peer_id.clone();
    write_proposal(&app.home, &proposal)?;

    if proposal.proposal_type == "policy" {
        let parts: Vec<&str> = proposal.details.split(':').collect();
        if parts.len() >= 4 {
            let _ = create_policy(app, parts[0], parts[1], parts[2], parts[3]);
        } else {
            update_policy(app, &proposal.subject_id, None, Some("true"))?;
        }
    }

    record_event(
        app,
        &proposal.org_id,
        "governance",
        "approve",
        &identity.peer_id,
        &proposal.id,
    )?;
    Ok(proposal)
}

pub fn reject_proposal(app: &App, id: &str) -> Result<GovernanceProposal> {
    let mut proposal = find_proposal(app, id)?;
    let identity = app.ensure_identity()?;
    proposal.state = "rejected".into();
    write_proposal(&app.home, &proposal)?;
    record_event(
        app,
        &proposal.org_id,
        "governance",
        "reject",
        &identity.peer_id,
        &proposal.id,
    )?;
    Ok(proposal)
}

pub fn inspect_governance(app: &App, org_ref: &str) -> Result<Vec<GovernanceProposal>> {
    list_proposals(app, Some(org_ref))
}
