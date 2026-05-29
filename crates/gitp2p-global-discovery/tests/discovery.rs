use gitp2p_federation::create_domain;
use gitp2p_gateway::{create_gateway, exchange_routes};
use gitp2p_global_discovery::{discover_domains, discover_gateways};
use gitp2p_peering::connect_domains;
use gitp2p_vault::App;

#[test]
fn global_discovery_from_peering_fixture() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-v5-discovery-{}",
        gitp2p_metadata::util::stable_id("discovery-test")
    ));
    let _ = std::fs::remove_dir_all(&root);
    let home_a = root.join("home-a");
    let home_b = root.join("home-b");

    let app_a = App::with_home(home_a.clone());
    app_a.ensure_home().unwrap();
    app_a.ensure_identity().unwrap();
    let domain_a = create_domain(&app_a, "domain-a").unwrap();
    let gw_a = create_gateway(&app_a, &domain_a.id, "127.0.0.1", 8443).unwrap();

    let app_b = App::with_home(home_b.clone());
    app_b.ensure_home().unwrap();
    app_b.ensure_identity().unwrap();
    let domain_b = create_domain(&app_b, "domain-b").unwrap();
    let gw_b = create_gateway(&app_b, &domain_b.id, "127.0.0.2", 8443).unwrap();

    connect_domains(&app_a, &domain_a.id, &domain_b.id, Some(&gw_a.id), Some(&gw_b.id)).unwrap();
    exchange_routes(&app_a, &gw_a.id, &gw_b.id, "route-a-b").unwrap();

    let domains = discover_domains(&app_a).unwrap();
    assert!(domains.iter().any(|d| d.id == domain_a.id));
    assert!(domains.iter().any(|d| d.id == domain_b.id));

    let gateways = discover_gateways(&app_a).unwrap();
    assert!(gateways.iter().any(|g| g.id == gw_a.id));
}
