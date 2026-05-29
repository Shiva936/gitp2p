use gitp2p_runtime::agents::optimization::plan_optimization;
use gitp2p_runtime::decision::{execute_decision_replay, list_decisions, list_plans, replay_decision};
use gitp2p_runtime::policy::{create_policy, evaluate_policy};
use gitp2p_runtime::{automation_tick};
use gitp2p_core::trust::write_peer;
use gitp2p_core::Peer;
use gitp2p_testing::setup_vault_with_repo;

#[test]
fn decision_replay_is_deterministic() {
    let app = setup_vault_with_repo("replay-decision");
    create_policy(
        &app,
        "checkpoint-policy",
        "checkpoint",
        "team",
        "checkpoint_interval_hours=4",
    )
    .unwrap();

    let first = automation_tick(&app, "team", true).unwrap();
    assert!(!first.decisions.is_empty());

    let decisions = list_decisions(&app).unwrap();
    let decision = decisions.first().unwrap();
    let replayed = replay_decision(&app, &decision.id).unwrap();
    assert_eq!(replayed.id, decision.id);
    assert_eq!(replayed.action, decision.action);
    assert_eq!(replayed.agent, decision.agent);
    assert!(!replayed.signature.is_empty());
}

#[test]
fn replay_execution_dry_run_updates_plan() {
    let app = setup_vault_with_repo("replay-exec");
    create_policy(
        &app,
        "checkpoint-policy",
        "checkpoint",
        "team",
        "checkpoint_interval_hours=4",
    )
    .unwrap();

    let tick = automation_tick(&app, "team", true).unwrap();
    let decision_id = tick.decisions[0].id.clone();
    let report = execute_decision_replay(&app, &decision_id, true).unwrap();
    assert_eq!(report.status, "replay-dry-run");
    if !report.plan_id.is_empty() {
        let plan = list_plans(&app, None)
            .unwrap()
            .into_iter()
            .find(|p| p.id == report.plan_id)
            .unwrap();
        assert_eq!(plan.status, "replay-dry-run");
    }
}

#[test]
fn optimization_agent_runs_with_multiple_peers() {
    let app = setup_vault_with_repo("replay-opt");
    let identity = app.ensure_identity().unwrap();
    for (id, port) in [("peer-a", 9135_u16), ("peer-b", 9136_u16)] {
        let peer = Peer {
            id: id.into(),
            public_key: identity.public_key.clone(),
            home: std::path::PathBuf::new(),
            trust_state: "trusted".into(),
            capabilities: "sync".into(),
            vaults: String::new(),
            discovered_at: gitp2p_core::util::timestamp(),
            listen_port: port,
        };
        write_peer(&app.home, &peer).unwrap();
    }

    create_policy(&app, "replica-policy", "replica", "team", "min_replicas=2").unwrap();
    let policies = evaluate_policy(&app, "team", None).unwrap();
    let decision = plan_optimization(&app, "team", &policies)
        .unwrap()
        .expect("optimization decision");
    assert_eq!(decision.agent, "optimization");
}
