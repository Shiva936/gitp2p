use gitp2p_enterprise::{create_organization, inspect_organization, list_organizations};
use gitp2p_core::App;

#[test]
fn org_lifecycle() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-org-{}",
        gitp2p_core::util::stable_id("org-test")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();

    let org = create_organization(&app, "acme").unwrap();
    assert_eq!(org.name, "acme");
    assert_eq!(list_organizations(&app).unwrap().len(), 1);

    let inspected = inspect_organization(&app, "acme").unwrap();
    assert_eq!(inspected.id, org.id);
}
