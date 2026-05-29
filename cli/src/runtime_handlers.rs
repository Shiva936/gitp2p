use gitp2p_enterprise::{delegate_admin, inspect_admin, revoke_admin};
use gitp2p_enterprise::{export_audit, search_audit};
use gitp2p_enterprise::compliance::{generate_report, inspect_compliance};
use gitp2p_runtime::{find_decision, list_decisions};
use gitp2p_enterprise::org_trust::{establish_trust, inspect_trust, revoke_trust};
use gitp2p_runtime::explain::{find_explanation, format_explanation, inspect_history};
use gitp2p_enterprise::{
    approve_proposal, create_proposal, inspect_governance, list_proposals, reject_proposal,
    review_proposal,
};
use gitp2p_runtime::calculate_health;
use gitp2p_core::Result;
use gitp2p_enterprise::{
    add_member, create_organization, inspect_organization, list_organizations, remove_member,
    update_organization,
};
use gitp2p_runtime::agents::recovery::inspect_recovery_plan;
use gitp2p_enterprise::{assign_role, list_roles, require_permission, revoke_role};
use gitp2p_runtime::{automation_pause, automation_resume, automation_tick};
use gitp2p_runtime::policy::{
    create_policy, delete_policy, find_policy, list_policies, update_policy,
};
use gitp2p_runtime::agents::sync::inspect_sync_plan;
use gitp2p_enterprise::{assign_member, create_team, inspect_team, list_teams};
use gitp2p_runtime::agents::trust::list_recommendations;
use gitp2p_enterprise::visibility::generate_report as visibility_report;
use gitp2p_core::App;

pub fn cmd_runtime_policy_create(
    app: &App,
    name: &str,
    kind: &str,
    vault: &str,
    fields: &str,
) -> Result<()> {
    let policy = create_policy(app, name, kind, vault, fields)?;
    println!(
        "policy created: {} ({}) kind={} vault={}",
        policy.name, policy.id, policy.kind, policy.scope_vault
    );
    Ok(())
}

pub fn cmd_runtime_policy_inspect(app: &App, reference: Option<String>) -> Result<()> {
    if let Some(reference) = reference {
        let policy = find_policy(app, &reference)?;
        println!("policy {}", policy.id);
        println!("  name: {}", policy.name);
        println!("  kind: {}", policy.kind);
        println!("  vault: {}", policy.scope_vault);
        println!("  fields: {}", policy.fields);
        println!("  active: {}", policy.active);
    } else {
        for policy in list_policies(app)? {
            println!(
                "{} kind={} vault={} active={}",
                policy.name, policy.kind, policy.scope_vault, policy.active
            );
        }
    }
    Ok(())
}

pub fn cmd_runtime_policy_update(
    app: &App,
    reference: &str,
    fields: Option<String>,
    active: Option<String>,
) -> Result<()> {
    let policy = update_policy(
        app,
        reference,
        fields.as_deref(),
        active.as_deref(),
    )?;
    println!("policy updated: {}", policy.id);
    Ok(())
}

pub fn cmd_runtime_policy_delete(app: &App, reference: &str) -> Result<()> {
    let policy = delete_policy(app, reference)?;
    println!("policy deleted: {}", policy.id);
    Ok(())
}

pub fn cmd_sync_plan(app: &App, vault: &str) -> Result<()> {
    for plan in inspect_sync_plan(app, vault)? {
        println!(
            "sync plan {} repo={} peer={} status={}",
            plan.id, plan.repo_id, plan.target_peer, plan.status
        );
    }
    Ok(())
}

pub fn cmd_sync_explain(app: &App, decision_id: Option<String>) -> Result<()> {
    let decision = if let Some(id) = decision_id {
        find_decision(app, &id)?
    } else {
        list_decisions(app)?
            .into_iter()
            .find(|d| d.agent == "sync")
            .ok_or_else(|| gitp2p_core::AppError::new("no sync decisions found"))?
    };
    let explanation = find_explanation(app, &decision.id)?;
    println!("{}", format_explanation(&explanation));
    Ok(())
}

pub fn cmd_replica_explain(app: &App, decision_id: Option<String>) -> Result<()> {
    let decision = if let Some(id) = decision_id {
        find_decision(app, &id)?
    } else {
        list_decisions(app)?
            .into_iter()
            .find(|d| d.agent == "replica")
            .ok_or_else(|| gitp2p_core::AppError::new("no replica decisions found"))?
    };
    let explanation = find_explanation(app, &decision.id)?;
    println!("{}", format_explanation(&explanation));
    Ok(())
}

pub fn cmd_checkpoint_explain(app: &App, decision_id: Option<String>) -> Result<()> {
    let decision = if let Some(id) = decision_id {
        find_decision(app, &id)?
    } else {
        list_decisions(app)?
            .into_iter()
            .find(|d| d.agent == "checkpoint")
            .ok_or_else(|| gitp2p_core::AppError::new("no checkpoint decisions found"))?
    };
    let explanation = find_explanation(app, &decision.id)?;
    println!("{}", format_explanation(&explanation));
    Ok(())
}

pub fn cmd_recovery_plan(app: &App, vault: &str) -> Result<()> {
    for plan in inspect_recovery_plan(app, vault)? {
        println!(
            "recovery plan {} repo={} action={} status={}",
            plan.id, plan.repo_id, plan.action, plan.status
        );
    }
    Ok(())
}

pub fn cmd_trust_recommend(app: &App) -> Result<()> {
    for rec in list_recommendations(app)? {
        println!(
            "peer={} recommendation={} reason={}",
            rec.peer_id, rec.recommendation, rec.reason
        );
    }
    Ok(())
}

pub fn cmd_trust_explain(app: &App, decision_id: Option<String>) -> Result<()> {
    let decision = if let Some(id) = decision_id {
        find_decision(app, &id)?
    } else {
        list_decisions(app)?
            .into_iter()
            .find(|d| d.agent == "trust")
            .ok_or_else(|| gitp2p_core::AppError::new("no trust decisions found"))?
    };
    let explanation = find_explanation(app, &decision.id)?;
    println!("{}", format_explanation(&explanation));
    Ok(())
}

pub fn cmd_health_inspect(app: &App, vault: &str) -> Result<()> {
    let report = calculate_health(app, vault)?;
    println!("health report {}", report.id);
    println!("  sync: {}", report.sync_score);
    println!("  replica: {}", report.replica_score);
    println!("  recovery: {}", report.recovery_score);
    println!("  trust: {}", report.trust_score);
    println!("  topology: {}", report.topology_score);
    if !report.risks.is_empty() {
        println!("  risks: {}", report.risks);
    }
    Ok(())
}

pub fn cmd_automation_run(app: &App, vault: &str, dry_run: bool) -> Result<()> {
    let report = automation_tick(app, vault, dry_run)?;
    if report.paused {
        println!("automation paused; no actions taken");
        return Ok(());
    }
    println!(
        "automation tick complete: {} decisions{}",
        report.decisions.len(),
        if dry_run { " (dry-run)" } else { "" }
    );
    for decision in &report.decisions {
        println!("  {} {} -> {}", decision.agent, decision.action, decision.status);
    }
    if let Some(health) = report.health {
        println!(
            "health: sync={} replica={} recovery={}",
            health.sync_score, health.replica_score, health.recovery_score
        );
    }
    Ok(())
}

pub fn cmd_automation_pause(app: &App) -> Result<()> {
    automation_pause(app)?;
    println!("automation paused");
    Ok(())
}

pub fn cmd_automation_resume(app: &App) -> Result<()> {
    automation_resume(app)?;
    println!("automation resumed");
    Ok(())
}

pub fn cmd_explain_decision(app: &App, decision_id: Option<String>) -> Result<()> {
    if let Some(id) = decision_id {
        let explanation = find_explanation(app, &id)?;
        println!("{}", format_explanation(&explanation));
    } else {
        for explanation in inspect_history(app)? {
            println!("{}", format_explanation(&explanation));
            println!("---");
        }
    }
    Ok(())
}

pub fn cmd_org_create(app: &App, name: &str) -> Result<()> {
    let org = create_organization(app, name)?;
    println!("organization created: {} ({})", org.name, org.id);
    Ok(())
}

pub fn cmd_org_inspect(app: &App, reference: Option<String>) -> Result<()> {
    if let Some(reference) = reference {
        let org = inspect_organization(app, &reference)?;
        println!("organization {}", org.id);
        println!("  name: {}", org.name);
        println!("  owner: {}", org.owner_peer_id);
        println!("  members: {}", org.members);
    } else {
        for org in list_organizations(app)? {
            println!("{} owner={}", org.name, org.owner_peer_id);
        }
    }
    Ok(())
}

pub fn cmd_org_update(app: &App, reference: &str, name: Option<String>) -> Result<()> {
    let org = update_organization(app, reference, name.as_deref())?;
    println!("organization updated: {}", org.id);
    Ok(())
}

pub fn cmd_org_member_add(app: &App, reference: &str, peer_id: &str) -> Result<()> {
    let org = add_member(app, reference, peer_id)?;
    println!("member added to {}: {}", org.name, peer_id);
    Ok(())
}

pub fn cmd_org_member_remove(app: &App, reference: &str, peer_id: &str) -> Result<()> {
    let org = remove_member(app, reference, peer_id)?;
    println!("member removed from {}: {}", org.name, peer_id);
    Ok(())
}

pub fn cmd_team_create(app: &App, org: &str, name: &str) -> Result<()> {
    let team = create_team(app, org, name)?;
    println!("team created: {} ({})", team.name, team.id);
    Ok(())
}

pub fn cmd_team_inspect(app: &App, reference: Option<String>, org: Option<String>) -> Result<()> {
    if let Some(reference) = reference {
        let team = inspect_team(app, &reference)?;
        println!("team {}", team.id);
        println!("  name: {}", team.name);
        println!("  org: {}", team.org_id);
        println!("  members: {}", team.members);
    } else {
        for team in list_teams(app, org.as_deref())? {
            println!("{} org={} members={}", team.name, team.org_id, team.members);
        }
    }
    Ok(())
}

pub fn cmd_team_member_add(app: &App, team: &str, peer_id: &str) -> Result<()> {
    let team = assign_member(app, team, peer_id)?;
    println!("member added to team {}: {}", team.name, peer_id);
    Ok(())
}

pub fn cmd_role_assign(app: &App, org: &str, peer_id: &str, role: &str) -> Result<()> {
    let assignment = assign_role(app, org, peer_id, role)?;
    println!("role assigned: {} -> {} ({})", peer_id, role, assignment.id);
    Ok(())
}

pub fn cmd_role_revoke(app: &App, org: &str, peer_id: &str) -> Result<()> {
    let assignment = revoke_role(app, org, peer_id)?;
    println!("role revoked: {} was {}", peer_id, assignment.role);
    Ok(())
}

pub fn cmd_role_inspect(app: &App, org: &str) -> Result<()> {
    for role in list_roles(app, org)? {
        println!("{} -> {}", role.peer_id, role.role);
    }
    Ok(())
}

pub fn cmd_governance_propose(
    app: &App,
    org: &str,
    proposal_type: &str,
    subject_id: &str,
    details: &str,
) -> Result<()> {
    let proposal = create_proposal(app, org, proposal_type, subject_id, details)?;
    println!("proposal created: {} state={}", proposal.id, proposal.state);
    Ok(())
}

pub fn cmd_governance_review(app: &App, id: &str) -> Result<()> {
    let proposal = review_proposal(app, id)?;
    println!("proposal reviewed: {} state={}", proposal.id, proposal.state);
    Ok(())
}

pub fn cmd_governance_approve(app: &App, org: &str, id: &str) -> Result<()> {
    let identity = app.ensure_identity()?;
    require_permission(app, org, &identity.peer_id, "policy_approve")?;
    let proposal = approve_proposal(app, id)?;
    println!("proposal approved: {} state={}", proposal.id, proposal.state);
    Ok(())
}

pub fn cmd_governance_reject(app: &App, id: &str) -> Result<()> {
    let proposal = reject_proposal(app, id)?;
    println!("proposal rejected: {} state={}", proposal.id, proposal.state);
    Ok(())
}

pub fn cmd_governance_inspect(app: &App, org: &str) -> Result<()> {
    for proposal in inspect_governance(app, org)? {
        println!(
            "{} type={} state={} subject={}",
            proposal.id, proposal.proposal_type, proposal.state, proposal.subject_id
        );
    }
    Ok(())
}

pub fn cmd_audit_search(
    app: &App,
    org: Option<String>,
    source: Option<String>,
    action: Option<String>,
) -> Result<()> {
    for event in search_audit(app, org.as_deref(), source.as_deref(), action.as_deref())? {
        println!(
            "{} {} {} {} {}",
            event.created_at, event.source, event.action, event.actor, event.details
        );
    }
    Ok(())
}

pub fn cmd_audit_export(app: &App, org: Option<String>) -> Result<()> {
    println!("{}", export_audit(app, org.as_deref())?);
    Ok(())
}

pub fn cmd_compliance_inspect(app: &App, org: &str) -> Result<()> {
    let report = inspect_compliance(app, org)?;
    println!("compliance: {} status={}", report.id, report.status);
    if !report.findings.is_empty() {
        println!("  findings: {}", report.findings);
    }
    Ok(())
}

pub fn cmd_compliance_report(app: &App, org: &str) -> Result<()> {
    println!("{}", generate_report(app, org)?);
    Ok(())
}

pub fn cmd_admin_delegate(app: &App, org: &str, delegate: &str, scope: &str) -> Result<()> {
    let delegation = delegate_admin(app, org, delegate, scope)?;
    println!("admin delegated to {} scope={}", delegation.delegate, delegation.scope);
    Ok(())
}

pub fn cmd_admin_revoke(app: &App, org: &str, delegate: &str) -> Result<()> {
    revoke_admin(app, org, delegate)?;
    println!("admin delegation revoked for {}", delegate);
    Ok(())
}

pub fn cmd_admin_inspect(app: &App, org: &str) -> Result<()> {
    for d in inspect_admin(app, org)? {
        println!("{} -> {} scope={} state={}", d.delegator, d.delegate, d.scope, d.state);
    }
    Ok(())
}

pub fn cmd_org_trust_establish(app: &App, org: &str, remote_org: &str) -> Result<()> {
    let trust = establish_trust(app, org, remote_org)?;
    println!("org trust established: {} -> {}", trust.org_id, trust.remote_org_id);
    Ok(())
}

pub fn cmd_org_trust_inspect(app: &App, org: &str, remote: Option<String>) -> Result<()> {
    for trust in inspect_trust(app, org, remote.as_deref())? {
        println!("{} -> {} state={}", trust.org_id, trust.remote_org_id, trust.state);
    }
    Ok(())
}

pub fn cmd_org_trust_revoke(app: &App, org: &str, remote_org: &str) -> Result<()> {
    revoke_trust(app, org, remote_org)?;
    println!("org trust revoked: {}", remote_org);
    Ok(())
}

pub fn cmd_policy_history(app: &App, org: Option<String>) -> Result<()> {
    for proposal in list_proposals(app, org.as_deref())? {
        if proposal.proposal_type == "policy" {
            println!(
                "{} state={} subject={} at={}",
                proposal.id, proposal.state, proposal.subject_id, proposal.created_at
            );
        }
    }
    Ok(())
}

pub fn cmd_visibility_report(app: &App, org: &str) -> Result<()> {
    println!("{}", visibility_report(app, org)?);
    Ok(())
}

pub fn cmd_replay_decision(app: &App, decision_id: &str, dry_run: bool) -> Result<()> {
    let report = gitp2p_runtime::execute_decision_replay(app, decision_id, dry_run)?;
    println!(
        "decision replayed: {} plan={} agent={} action={} status={}",
        report.decision_id, report.plan_id, report.agent, report.action, report.status
    );
    Ok(())
}

pub fn cmd_automation_run_gated(app: &App, org: &str, vault: &str, dry_run: bool) -> Result<()> {
    let identity = app.ensure_identity()?;
    require_permission(app, org, &identity.peer_id, "automation_run")?;
    cmd_automation_run(app, vault, dry_run)
}
