use gitp2p_runtime::decision::{execute_decision_replay, list_plans};
use gitp2p_runtime::policy::create_policy;
use gitp2p_runtime::{automation_tick};
use gitp2p_testing::setup_vault_with_repo;

#[test]
fn replay_decision_dry_run_updates_plan_status() {
    let app = setup_vault_with_repo("int-replay-e2e");
    create_policy(
        &app,
        "checkpoint-policy",
        "checkpoint",
        "team",
        "checkpoint_interval_hours=4",
    )
    .unwrap();

    let tick = automation_tick(&app, "team", true).unwrap();
    assert!(!tick.decisions.is_empty());
    let decision_id = tick.decisions[0].id.clone();

    let report = execute_decision_replay(&app, &decision_id, true).unwrap();
    assert_eq!(report.status, "replay-dry-run");

    if !report.plan_id.is_empty() {
        let plans = list_plans(&app, None).unwrap();
        let plan = plans.iter().find(|p| p.id == report.plan_id).unwrap();
        assert_eq!(plan.status, "replay-dry-run");
    }
}
