use gitp2p_trust::{create_delegation, inspect_delegation_chain, validate_delegation_chain};
use gitp2p_vault::App;

#[test]
fn delegation_chain_validation() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v5-delegation-{}",
        gitp2p_metadata::util::stable_id("delegation-test")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();
    let identity = app.ensure_identity().unwrap();

    let root = create_delegation(
        &app.home,
        &identity,
        "domain-alpha",
        "domain",
        "sync",
        None,
    )
    .unwrap();
    let child = create_delegation(
        &app.home,
        &identity,
        "gateway-beta",
        "gateway",
        "route",
        Some(&root.id),
    )
    .unwrap();

    let chain = inspect_delegation_chain(&app.home, Some(&child.id)).unwrap();
    assert_eq!(chain.len(), 2);
    validate_delegation_chain(&app.home, &identity, &chain).unwrap();
}
