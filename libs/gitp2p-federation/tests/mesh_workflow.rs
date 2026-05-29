use gitp2p_federation::multi_hop_reconcile;
use gitp2p_federation::{relay_status, set_relay_enabled};
use gitp2p_federation::{discover_routes, select_route};
use gitp2p_federation::topology_summary;
use gitp2p_core::{create_vault, App};

#[test]
fn mesh_routing_topology() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v4-{}",
        gitp2p_core::util::stable_id("mesh")
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();
    create_vault(&app, "fed").unwrap();

    set_relay_enabled(&app, true).unwrap();
    assert!(relay_status(&app).unwrap().enabled);

    let routes = discover_routes(&app, "peer-dest").unwrap();
    assert!(select_route(&routes).is_none() || !routes.is_empty());

    let summary = topology_summary(&app).unwrap();
    assert!(summary.contains("vaults"));

    let dups = multi_hop_reconcile(&app, "repo-none").unwrap();
    assert!(dups.is_empty());
}
