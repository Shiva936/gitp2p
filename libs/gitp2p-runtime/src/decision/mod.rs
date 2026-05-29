mod layout;

pub use layout::*;

use crate::explain::record_explanation;
use gitp2p_core::{
    field, optional_field, read_kv, write_kv, Result, RuntimeDecision, RuntimePlan,
};
use crate::agents::recovery::plan_recovery;
use crate::agents::replica::plan_replicas;
use crate::policy::ensure_runtime_layout;
use crate::policy::evaluate_policy;
use crate::agents::sync::plan_sync;
use gitp2p_core::trust::{sign_bytes, verify_bytes};
use crate::agents::trust::plan_trust;
use gitp2p_core::App;

pub fn decision_payload(decision: &RuntimeDecision) -> String {
    format!(
        "decision:{}:{}:{}:{}",
        decision.id, decision.agent, decision.action, decision.policy_id
    )
}

pub fn read_decision(path: &std::path::Path) -> Result<RuntimeDecision> {
    let map = read_kv(path)?;
    Ok(RuntimeDecision {
        id: field(&map, "id")?,
        agent: field(&map, "agent")?,
        phase: field(&map, "phase")?,
        policy_id: optional_field(&map, "policy_id"),
        action: field(&map, "action")?,
        expected_outcome: optional_field(&map, "expected_outcome"),
        status: field(&map, "status")?,
        vault_id: optional_field(&map, "vault_id"),
        repo_id: optional_field(&map, "repo_id"),
        details: optional_field(&map, "details"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_decision(home: &std::path::Path, decision: &RuntimeDecision) -> Result<()> {
    write_kv(
        &decisions_dir(home).join(&decision.id),
        &[
            ("id", &decision.id),
            ("agent", &decision.agent),
            ("phase", &decision.phase),
            ("policy_id", &decision.policy_id),
            ("action", &decision.action),
            ("expected_outcome", &decision.expected_outcome),
            ("status", &decision.status),
            ("vault_id", &decision.vault_id),
            ("repo_id", &decision.repo_id),
            ("details", &decision.details),
            ("created_at", &decision.created_at),
            ("signature", &decision.signature),
            ("signed_by", &decision.signed_by),
            ("signed_at", &decision.signed_at),
        ],
    )
}

pub fn write_plan(home: &std::path::Path, plan: &RuntimePlan) -> Result<()> {
    write_kv(
        &plans_dir(home).join(&plan.id),
        &[
            ("id", &plan.id),
            ("kind", &plan.kind),
            ("decision_id", &plan.decision_id),
            ("vault_id", &plan.vault_id),
            ("repo_id", &plan.repo_id),
            ("target_peer", &plan.target_peer),
            ("action", &plan.action),
            ("status", &plan.status),
            ("created_at", &plan.created_at),
        ],
    )
}

pub fn list_decisions(app: &App) -> Result<Vec<RuntimeDecision>> {
    ensure_runtime_layout(&app.home)?;
    let dir = decisions_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut decisions = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            decisions.push(read_decision(&entry.path())?);
        }
    }
    decisions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(decisions)
}

pub fn find_decision(app: &App, id: &str) -> Result<RuntimeDecision> {
    let path = decisions_dir(&app.home).join(id);
    if path.exists() {
        return read_decision(&path);
    }
    list_decisions(app)?
        .into_iter()
        .find(|d| d.id == id)
        .ok_or_else(|| gitp2p_core::AppError::new(format!("decision '{id}' not found")))
}

fn sign_decision(identity: &gitp2p_core::Identity, decision: &mut RuntimeDecision) -> Result<()> {
    let payload = decision_payload(decision);
    decision.signature = sign_bytes(identity, payload.as_bytes())?;
    decision.signed_by = identity.peer_id.clone();
    decision.signed_at = gitp2p_core::util::timestamp();
    Ok(())
}

pub fn run_tick(app: &App, vault: &str, dry_run: bool) -> Result<Vec<RuntimeDecision>> {
    ensure_runtime_layout(&app.home)?;
    let policies = evaluate_policy(app, vault, None)?;
    let identity = app.ensure_identity()?;
    let mut decisions = Vec::new();

    // Priority: recovery > replication > sync > trust
    if let Some((decision, plan)) = plan_recovery(app, vault, &policies)? {
        let mut d = decision;
        sign_decision(&identity, &mut d)?;
        write_decision(&app.home, &d)?;
        write_plan(&app.home, &plan)?;
        record_explanation(app, &d)?;
        if !dry_run {
            crate::agents::recovery::execute_plan(app, &plan)?;
        }
        decisions.push(d);
    }

    if let Some((decision, plan)) = crate::agents::sync::plan_checkpoint(app, vault, &policies)? {
        let mut d = decision;
        sign_decision(&identity, &mut d)?;
        write_decision(&app.home, &d)?;
        write_plan(&app.home, &plan)?;
        record_explanation(app, &d)?;
        if !dry_run {
            crate::agents::sync::execute_checkpoint_plan(app, &plan)?;
        }
        decisions.push(d);
    }

    if let Some((decision, plan)) = plan_replicas(app, vault, &policies)? {
        let mut d = decision;
        sign_decision(&identity, &mut d)?;
        write_decision(&app.home, &d)?;
        write_plan(&app.home, &plan)?;
        record_explanation(app, &d)?;
        if !dry_run {
            crate::agents::replica::execute_plan(app, &plan)?;
        }
        decisions.push(d);
    }

    if let Some((decision, plan)) = plan_sync(app, vault, &policies)? {
        let mut d = decision;
        sign_decision(&identity, &mut d)?;
        write_decision(&app.home, &d)?;
        write_plan(&app.home, &plan)?;
        record_explanation(app, &d)?;
        if !dry_run {
            crate::agents::sync::execute_plan(app, &plan)?;
        }
        decisions.push(d);
    }

    if let Some((decision, _plan)) = plan_trust(app, vault, &policies)? {
        let mut d = decision;
        sign_decision(&identity, &mut d)?;
        write_decision(&app.home, &d)?;
        record_explanation(app, &d)?;
        decisions.push(d);
    }

    if let Some(mut d) = crate::agents::optimization::plan_optimization(app, vault, &policies)? {
        sign_decision(&identity, &mut d)?;
        write_decision(&app.home, &d)?;
        record_explanation(app, &d)?;
        decisions.push(d);
    }

    Ok(decisions)
}

pub fn replay_decision(app: &App, decision_id: &str) -> Result<RuntimeDecision> {
    let decision = find_decision(app, decision_id)?;
    let identity = app.ensure_identity()?;
    verify_decision(&decision, &identity.public_key)?;
    Ok(decision)
}

#[derive(Clone, Debug)]
pub struct ReplayReport {
    pub decision_id: String,
    pub plan_id: String,
    pub agent: String,
    pub action: String,
    pub status: String,
}

pub fn find_plan_for_decision(app: &App, decision_id: &str) -> Result<Option<RuntimePlan>> {
    Ok(list_plans(app, None)?
        .into_iter()
        .find(|p| p.decision_id == decision_id))
}

pub fn execute_decision_replay(app: &App, decision_id: &str, dry_run: bool) -> Result<ReplayReport> {
    let decision = replay_decision(app, decision_id)?;
    let plan = find_plan_for_decision(app, decision_id)?;

    if !dry_run {
        if let Some(ref plan) = plan {
            match plan.kind.as_str() {
                "checkpoint" => crate::agents::sync::execute_checkpoint_plan(app, plan)?,
                "sync" => crate::agents::sync::execute_plan(app, plan)?,
                "replica" => crate::agents::replica::execute_plan(app, plan)?,
                "recovery" => crate::agents::recovery::execute_plan(app, plan)?,
                _ => {}
            }
        }
    }

    let status = if dry_run {
        "replay-dry-run"
    } else {
        "replayed"
    };

    if let Some(mut plan) = plan {
        plan.status = status.into();
        write_plan(&app.home, &plan)?;
        let mut replay_decision = decision.clone();
        replay_decision.phase = "replay".into();
        record_explanation(app, &replay_decision)?;
        return Ok(ReplayReport {
            decision_id: decision.id,
            plan_id: plan.id,
            agent: decision.agent,
            action: decision.action,
            status: status.into(),
        });
    }

    let mut replay_decision = decision.clone();
    replay_decision.phase = "replay".into();
    record_explanation(app, &replay_decision)?;
    Ok(ReplayReport {
        decision_id: decision.id,
        plan_id: String::new(),
        agent: decision.agent,
        action: decision.action,
        status: status.into(),
    })
}

pub fn verify_decision(decision: &RuntimeDecision, public_key: &str) -> Result<()> {
    if decision.signature.is_empty() {
        return Ok(());
    }
    verify_bytes(
        public_key,
        decision_payload(decision).as_bytes(),
        &decision.signature,
    )
}

pub fn list_plans(app: &App, kind: Option<&str>) -> Result<Vec<RuntimePlan>> {
    ensure_runtime_layout(&app.home)?;
    let dir = plans_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut plans = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = read_kv(&entry.path())?;
            let plan = RuntimePlan {
                id: field(&map, "id")?,
                kind: field(&map, "kind")?,
                decision_id: optional_field(&map, "decision_id"),
                vault_id: optional_field(&map, "vault_id"),
                repo_id: optional_field(&map, "repo_id"),
                target_peer: optional_field(&map, "target_peer"),
                action: field(&map, "action")?,
                status: field(&map, "status")?,
                created_at: field(&map, "created_at")?,
            };
            if kind.map(|k| plan.kind == k).unwrap_or(true) {
                plans.push(plan);
            }
        }
    }
    Ok(plans)
}
