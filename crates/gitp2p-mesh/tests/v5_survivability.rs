use gitp2p_federation::create_domain;
use gitp2p_gateway::create_gateway;
use gitp2p_peering::connect_domains;
use gitp2p_routing::{build_global_route, cache_global_route, failover_route, verify_route};
use gitp2p_vault::App;

#[test]
fn gateway_failover_reroute() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v5-survive-{}",
        gitp2p_metadata::util::stable_id("survivability")
    ));
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();

    let domain = create_domain(&app, "survive").unwrap();
    let gw = create_gateway(&app, &domain.id, "127.0.0.1", 8443).unwrap();
    connect_domains(
        &app,
        &domain.id,
        "remote-domain",
        Some(&gw.id),
        Some("remote-gw"),
    )
    .unwrap();

    let route = build_global_route(&app, "remote-domain").unwrap();
    cache_global_route(&app, &route).unwrap();
    verify_route(&app, &route.id).unwrap();

    let failover = failover_route(&app, &route.id).unwrap();
    assert_eq!(failover.state, "failover");
    assert!(failover.cost >= route.cost);
}
