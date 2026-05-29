use gitp2p_federation::{
    create_domain, find_domain, list_domains, remove_domain, update_domain_policy,
};
use gitp2p_core::App;

#[test]
fn domain_lifecycle() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v5-domain-{}",
        gitp2p_core::util::stable_id("domain-test")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();

    let domain = create_domain(&app, "alpha").unwrap();
    assert_eq!(domain.name, "alpha");
    assert!(!domain.signature.is_empty());

    let updated = update_domain_policy(&app, "alpha", "trust_policy", "open").unwrap();
    assert_eq!(updated.trust_policy, "open");

    let found = find_domain(&app, &domain.id).unwrap();
    assert_eq!(found.name, "alpha");
    assert_eq!(list_domains(&app).unwrap().len(), 1);

    remove_domain(&app, "alpha", true).unwrap();
    assert!(list_domains(&app).unwrap().is_empty());
}
