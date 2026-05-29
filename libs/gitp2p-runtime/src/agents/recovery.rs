use gitp2p_core::identity::{runtime_decision_id, runtime_plan_id};
use gitp2p_core::{Result, RuntimeDecision, RuntimePlan, RuntimePolicy};
use gitp2p_federation::recover_sources;
use crate::agents::replica::count_replicas;
use crate::policy::policy_field_u32;
use gitp2p_core::App;

pub fn evaluate_readiness(app: &App, vault: &str) -> Result<(u32, Vec<String>)> {
    let min_replicas = 2u32;
    let current = count_replicas(app, vault)?;
    let mut risks = Vec::new();
    if current < min_replicas {
        risks.push(format!("replica count {current} below minimum {min_replicas}"));
    }
    let repos = app.all_repos()?;
    for repo in &repos {
        let sources = recover_sources(app, &repo.id)?;
        if sources.is_empty() {
            risks.push(format!("no recovery sources for repo {}", repo.name));
        }
    }
    let score = if risks.is_empty() {
        100
    } else {
        (100u32).saturating_sub(risks.len() as u32 * 25)
    };
    Ok((score, risks))
}

pub fn plan_recovery(
    app: &App,
    vault: &str,
    policies: &[RuntimePolicy],
) -> Result<Option<(RuntimeDecision, RuntimePlan)>> {
    let recovery_policies: Vec<_> = policies.iter().filter(|p| p.kind == "recovery").collect();
    let threshold = recovery_policies
        .first()
        .map(|p| policy_field_u32(p, "recover_if_replicas_below", 2))
        .unwrap_or(2);

    let current = count_replicas(app, vault)?;
    if current >= threshold {
        return Ok(None);
    }

    let (_, risks) = evaluate_readiness(app, vault)?;
    if risks.is_empty() {
        return Ok(None);
    }

    let policy_id = recovery_policies
        .first()
        .map(|p| p.id.clone())
        .unwrap_or_default();
    let repos = app.all_repos()?;
    let repo_id = repos
        .first()
        .map(|r| r.id.clone())
        .unwrap_or_default();

    let decision_id = runtime_decision_id("recovery");
    let plan_id = runtime_plan_id("recovery");

    let decision = RuntimeDecision {
        id: decision_id.clone(),
        agent: "recovery".into(),
        phase: "plan".into(),
        policy_id,
        action: "increase_recovery_readiness".into(),
        expected_outcome: format!("Restore recovery readiness for vault {vault}"),
        status: "planned".into(),
        vault_id: vault.into(),
        repo_id: repo_id.clone(),
        details: risks.join(";"),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };

    let plan = RuntimePlan {
        id: plan_id,
        kind: "recovery".into(),
        decision_id,
        vault_id: vault.into(),
        repo_id,
        target_peer: String::new(),
        action: "plan_recovery".into(),
        status: "pending".into(),
        created_at: gitp2p_core::util::timestamp(),
    };

    Ok(Some((decision, plan)))
}

pub fn execute_plan(_app: &App, _plan: &RuntimePlan) -> Result<()> {
    // Recovery agent is plan-first; execution delegated to replication agent on next tick
    Ok(())
}

pub fn inspect_recovery_plan(app: &App, vault: &str) -> Result<Vec<RuntimePlan>> {
    let policies = crate::policy::evaluate_policy(app, vault, None)?;
    if let Some((_, plan)) = plan_recovery(app, vault, &policies)? {
        Ok(vec![plan])
    } else {
        Ok(Vec::new())
    }
}
