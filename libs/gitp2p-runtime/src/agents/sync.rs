use gitp2p_core::identity::{runtime_decision_id, runtime_plan_id};
use gitp2p_core::{Result, RuntimeDecision, RuntimePlan, RuntimePolicy};
use crate::policy::policy_field;
use gitp2p_sync::sync::sync_to_peer;
use gitp2p_core::App;

pub fn plan_sync(
    app: &App,
    vault: &str,
    policies: &[RuntimePolicy],
) -> Result<Option<(RuntimeDecision, RuntimePlan)>> {
    let sync_policies: Vec<_> = policies.iter().filter(|p| p.kind == "sync").collect();
    if sync_policies.is_empty() {
        return Ok(None);
    }
    let policy = &sync_policies[0];
    let peers = app.all_peers()?;
    let trusted: Vec<_> = peers
        .into_iter()
        .filter(|p| p.trust_state == "trusted")
        .collect();
    if trusted.is_empty() {
        return Ok(None);
    }
    let repos = app.all_repos()?;
    let repo = repos
        .into_iter()
        .find(|r| {
            app.find_vault(&r.vault_id)
                .map(|v| v.name == vault || v.id == vault)
                .unwrap_or(false)
        })
        .ok_or_else(|| gitp2p_core::AppError::new(format!("no repo in vault '{vault}'")))?;

    let priority = policy_field(policy, "sync_priority").unwrap_or_else(|| "normal".into());
    let peer = &trusted[0];
    let decision_id = runtime_decision_id("sync");
    let plan_id = runtime_plan_id("sync");

    let decision = RuntimeDecision {
        id: decision_id.clone(),
        agent: "sync".into(),
        phase: "plan".into(),
        policy_id: policy.id.clone(),
        action: format!("sync_to_peer:{}", peer.id),
        expected_outcome: format!("Synchronize repo {} with priority {}", repo.name, priority),
        status: "planned".into(),
        vault_id: vault.into(),
        repo_id: repo.id.clone(),
        details: format!("target_peer={}", peer.id),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };

    let plan = RuntimePlan {
        id: plan_id,
        kind: "sync".into(),
        decision_id,
        vault_id: vault.into(),
        repo_id: repo.id.clone(),
        target_peer: peer.id.clone(),
        action: "sync_to_peer".into(),
        status: "pending".into(),
        created_at: gitp2p_core::util::timestamp(),
    };

    Ok(Some((decision, plan)))
}

pub fn execute_plan(app: &App, plan: &RuntimePlan) -> Result<()> {
    sync_to_peer(app, Some(&plan.repo_id), &plan.target_peer, false, true)?;
    Ok(())
}

pub fn plan_checkpoint(
    app: &App,
    vault: &str,
    policies: &[RuntimePolicy],
) -> Result<Option<(RuntimeDecision, RuntimePlan)>> {
    let cp_policies: Vec<_> = policies.iter().filter(|p| p.kind == "checkpoint").collect();
    if cp_policies.is_empty() {
        return Ok(None);
    }
    let policy = &cp_policies[0];
    let repos = app.all_repos()?;
    let repo = repos
        .into_iter()
        .find(|r| {
            app.find_vault(&r.vault_id)
                .map(|v| v.name == vault || v.id == vault)
                .unwrap_or(false)
        })
        .ok_or_else(|| gitp2p_core::AppError::new(format!("no repo in vault '{vault}'")))?;

    if !repo.latest_checkpoint.is_empty() {
        if let Ok((_, _, checkpoint)) = app.find_checkpoint(&repo.latest_checkpoint) {
            if let Ok(head) =
                gitp2p_core::git::git_output(["rev-parse", "HEAD"], Some(&repo.path))
            {
                if head.trim() == checkpoint.commit {
                    return Ok(None);
                }
            }
        }
    }

    let decision_id = runtime_decision_id("checkpoint");
    let plan_id = runtime_plan_id("checkpoint");

    let decision = RuntimeDecision {
        id: decision_id.clone(),
        agent: "checkpoint".into(),
        phase: "plan".into(),
        policy_id: policy.id.clone(),
        action: "create_checkpoint".into(),
        expected_outcome: format!("Create checkpoint for repo {}", repo.name),
        status: "planned".into(),
        vault_id: vault.into(),
        repo_id: repo.id.clone(),
        details: policy.fields.clone(),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };

    let plan = RuntimePlan {
        id: plan_id,
        kind: "checkpoint".into(),
        decision_id,
        vault_id: vault.into(),
        repo_id: repo.id.clone(),
        target_peer: String::new(),
        action: "create_checkpoint".into(),
        status: "pending".into(),
        created_at: gitp2p_core::util::timestamp(),
    };

    Ok(Some((decision, plan)))
}

pub fn execute_checkpoint_plan(app: &App, plan: &RuntimePlan) -> Result<()> {
    gitp2p_core::create_checkpoint(app, Some(&plan.repo_id), true, false, false)?;
    Ok(())
}

pub fn inspect_sync_plan(app: &App, vault: &str) -> Result<Vec<RuntimePlan>> {
    let policies = crate::policy::evaluate_policy(app, vault, None)?;
    if let Some((_, plan)) = plan_sync(app, vault, &policies)? {
        Ok(vec![plan])
    } else {
        Ok(Vec::new())
    }
}
