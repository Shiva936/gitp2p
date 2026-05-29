use gitp2p_enterprise::{assign_role, create_organization, evaluate_permission, require_permission};
use gitp2p_core::App;

fn setup_org(suffix: &str) -> (App, gitp2p_core::Identity, gitp2p_core::Organization) {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-rbac-{}",
        gitp2p_core::util::stable_id(suffix)
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    let owner = app.ensure_identity().unwrap();
    let org = create_organization(&app, "acme").unwrap();
    (app, owner, org)
}

#[test]
fn rbac_role_matrix() {
    let (app, owner, org) = setup_org("rbac-matrix");
    let peers = [
        ("admin-peer", "administrator"),
        ("operator-peer", "operator"),
        ("auditor-peer", "auditor"),
        ("observer-peer", "observer"),
    ];
    for (peer, role) in peers {
        assign_role(&app, &org.name, peer, role).unwrap();
    }

    assert!(evaluate_permission(&app, &org.name, &owner.peer_id, "policy_approve").unwrap());
    assert!(evaluate_permission(&app, &org.name, "admin-peer", "policy_approve").unwrap());
    assert!(evaluate_permission(&app, &org.name, "operator-peer", "automation_run").unwrap());
    assert!(!evaluate_permission(&app, &org.name, "auditor-peer", "policy_approve").unwrap());
    assert!(evaluate_permission(&app, &org.name, "auditor-peer", "audit_read").unwrap());
    assert!(evaluate_permission(&app, &org.name, "observer-peer", "visibility_read").unwrap());
    assert!(!evaluate_permission(&app, &org.name, "observer-peer", "automation_run").unwrap());

    require_permission(&app, &org.name, "admin-peer", "policy_approve").unwrap();
    assert!(require_permission(&app, &org.name, "observer-peer", "policy_approve").is_err());
}

#[test]
fn rbac_compliance_read_restricted() {
    let (app, _owner, org) = setup_org("rbac-compliance");
    assign_role(&app, &org.name, "auditor-peer", "auditor").unwrap();
    assign_role(&app, &org.name, "operator-peer", "operator").unwrap();

    assert!(evaluate_permission(&app, &org.name, "auditor-peer", "compliance_read").unwrap());
    assert!(!evaluate_permission(&app, &org.name, "operator-peer", "compliance_read").unwrap());
}
