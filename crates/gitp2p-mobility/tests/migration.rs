use gitp2p_mobility::migrate_domain;
use gitp2p_federation::{create_domain, list_domains};
use gitp2p_vault::{create_vault, App};

#[test]
fn domain_migration_preserves_ids() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v5-mobility-{}",
        gitp2p_metadata::util::stable_id("mobility-test")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();
    let identity = app.ensure_identity().unwrap();
    create_domain(&app, "origin").unwrap();
    create_vault(&app, "primary").unwrap();

    let report = migrate_domain(&app, "target-region", None).unwrap();
    assert_eq!(report.peer_id, identity.peer_id);
    assert!(report.continuity_ok);
    assert!(!report.vault_ids.is_empty());
    assert!(list_domains(&app).unwrap().iter().any(|d| d.name.contains("target")));
}
