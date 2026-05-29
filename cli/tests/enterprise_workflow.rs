use gitp2p_enterprise::search_audit;
use gitp2p_enterprise::{approve_proposal, create_proposal};
use gitp2p_enterprise::create_organization;
use gitp2p_enterprise::{assign_role, evaluate_permission, require_permission};
use gitp2p_runtime::{automation_tick};
use gitp2p_core::{create_vault, App};

#[test]
fn enterprise_workflow() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v7-ent-{}",
        gitp2p_core::util::stable_id("v7-ent")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    let identity = app.ensure_identity().unwrap();

    let org = create_organization(&app, "acme").unwrap();
    assign_role(&app, &org.name, &identity.peer_id, "administrator").unwrap();
    create_vault(&app, "team").unwrap();

    let proposal = create_proposal(
        &app,
        &org.name,
        "policy",
        "replica-policy",
        "replica-policy:replica:team:min_replicas=2",
    )
    .unwrap();
    approve_proposal(&app, &proposal.id).unwrap();

    let _ = automation_tick(&app, "team", true).unwrap();

    let events = search_audit(&app, Some(&org.id), None, None).unwrap();
    assert!(events.iter().any(|e| e.action == "approve"));
    assert!(events.iter().any(|e| e.source == "governance"));

    assert!(evaluate_permission(&app, &org.name, &identity.peer_id, "automation_run").unwrap());
    require_permission(&app, &org.name, &identity.peer_id, "policy_approve").unwrap();

    let compliance = gitp2p_enterprise::evaluate_compliance(&app, &org.name).unwrap();
    assert!(!compliance.id.is_empty());

    let report = gitp2p_enterprise::visibility::generate_report(&app, &org.name).unwrap();
    assert!(report.contains("organization"));
}
