use gitp2p_federation::{
    build_global_route, cache_global_route, connect_domains, create_domain, create_gateway,
    failover_route, verify_route,
};
use gitp2p_testing::{simulate_relay_loss, temp_home};
use gitp2p_core::App;

#[test]
fn relay_loss_triggers_failover_route() {
    let home = temp_home("int-relay-loss");
    let _ = std::fs::remove_dir_all(&home);
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();

    let domain = create_domain(&app, "relay-test").unwrap();
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

    simulate_relay_loss(&app, &route.id).unwrap();
    let failover = failover_route(&app, &route.id).unwrap();
    assert_eq!(failover.state, "failover");
}
