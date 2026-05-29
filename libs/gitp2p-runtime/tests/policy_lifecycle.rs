use gitp2p_runtime::policy::{create_policy, evaluate_policy, list_policies};
use gitp2p_core::{create_vault, App};

#[test]
fn policy_lifecycle() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-policy-{}",
        gitp2p_core::util::stable_id("policy-test")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();
    create_vault(&app, "team").unwrap();

    let policy = create_policy(
        &app,
        "min-replicas",
        "replica",
        "team",
        "min_replicas=3",
    )
    .unwrap();
    assert_eq!(policy.kind, "replica");
    assert_eq!(list_policies(&app).unwrap().len(), 1);

    let active = evaluate_policy(&app, "team", None).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, policy.id);
}
