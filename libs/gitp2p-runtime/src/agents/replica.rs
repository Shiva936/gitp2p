use gitp2p_core::identity::{runtime_decision_id, runtime_plan_id};
use gitp2p_core::{Result, RuntimeDecision, RuntimePlan, RuntimePolicy};
use crate::policy::policy_field_u32;
use gitp2p_sync::sync::sync_to_peer;
use gitp2p_core::App;

pub fn count_replicas(app: &App, vault_name: &str) -> Result<u32> {
    let vault = app.find_vault(vault_name)?;
    gitp2p_core::util::count_files(vault.path.join("replication"))
        .map(|c| c as u32)
}

pub fn plan_replicas(
    app: &App,
    vault: &str,
    policies: &[RuntimePolicy],
) -> Result<Option<(RuntimeDecision, RuntimePlan)>> {
    let replica_policies: Vec<_> = policies.iter().filter(|p| p.kind == "replica").collect();
    if replica_policies.is_empty() {
        return Ok(None);
    }
    let policy = &replica_policies[0];
    let min_replicas = policy_field_u32(policy, "min_replicas", 1);
    let current = count_replicas(app, vault)?;
    if current >= min_replicas {
        return Ok(None);
    }

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

    let peer = &trusted[0];
    let decision_id = runtime_decision_id("replica");
    let plan_id = runtime_plan_id("replica");

    let decision = RuntimeDecision {
        id: decision_id.clone(),
        agent: "replica".into(),
        phase: "plan".into(),
        policy_id: policy.id.clone(),
        action: format!("create_replica:{}", peer.id),
        expected_outcome: format!(
            "Increase replicas from {current} to meet minimum {min_replicas}"
        ),
        status: "planned".into(),
        vault_id: vault.into(),
        repo_id: repo.id.clone(),
        details: format!("current={current},min={min_replicas},target_peer={}", peer.id),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };

    let plan = RuntimePlan {
        id: plan_id,
        kind: "replica".into(),
        decision_id,
        vault_id: vault.into(),
        repo_id: repo.id.clone(),
        target_peer: peer.id.clone(),
        action: "create_replica".into(),
        status: "pending".into(),
        created_at: gitp2p_core::util::timestamp(),
    };

    Ok(Some((decision, plan)))
}

pub fn execute_plan(app: &App, plan: &RuntimePlan) -> Result<()> {
    sync_to_peer(app, Some(&plan.repo_id), &plan.target_peer, false, true)?;
    Ok(())
}
