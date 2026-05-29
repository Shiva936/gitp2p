use std::fs;
use std::path::PathBuf;
use std::process::Command;

use gitp2p_federation::create_domain;
use gitp2p_gateway::create_gateway;
use gitp2p_peering::connect_domains;
use gitp2p_relay::set_relay_enabled;
use gitp2p_sync::{discover_filesystem, sync_to_peer};
use gitp2p_trust::write_peer;
use gitp2p_vault::{add_repo, create_vault, App};

fn run_git(args: &[&str], cwd: &PathBuf) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .expect("git should run");
    assert!(status.success());
}

fn init_repo(path: &PathBuf) {
    fs::create_dir_all(path).unwrap();
    run_git(&["init"], path);
    run_git(&["config", "user.email", "a@example.com"], path);
    run_git(&["config", "user.name", "A"], path);
}

#[test]
fn cross_domain_sync_fixture() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-v5-sync-{}",
        gitp2p_metadata::util::stable_id("global-sync")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let home_a = root.join("home-a");
    let home_b = root.join("home-b");
    let repo = root.join("repo");
    init_repo(&repo);
    fs::write(repo.join("lib.rs"), "pub fn ok() {}\n").unwrap();
    run_git(&["add", "lib.rs"], &repo);
    run_git(&["commit", "-m", "init"], &repo);

    let app_a = App::with_home(home_a.clone());
    app_a.ensure_home().unwrap();
    app_a.ensure_identity().unwrap();
    let domain_a = create_domain(&app_a, "domain-a").unwrap();
    let _gw_a = create_gateway(&app_a, &domain_a.id, "127.0.0.1", 8443).unwrap();
    create_vault(&app_a, "team").unwrap();
    let vault = app_a.find_vault("team").unwrap();
    add_repo(&app_a, &vault, Some(repo.to_string_lossy().into()), "trusted").unwrap();

    let app_b = App::with_home(home_b.clone());
    app_b.ensure_home().unwrap();
    app_b.ensure_identity().unwrap();
    let domain_b = create_domain(&app_b, "domain-b").unwrap();
    let gw_b = create_gateway(&app_b, &domain_b.id, "127.0.0.2", 8443).unwrap();
    connect_domains(&app_a, &domain_a.id, &domain_b.id, None, Some(&gw_b.id)).unwrap();

    let discovered = discover_filesystem(&app_a, &[home_b.clone()]).unwrap();
    assert!(!discovered.is_empty());
    let mut peer = discovered[0].clone();
    peer.trust_state = "trusted".into();
    write_peer(&app_a.home, &peer).unwrap();

    set_relay_enabled(&app_a, true).unwrap();
    let session = gitp2p_mesh::global_sync(&app_a, Some("repo"), &domain_b.id, false, false).unwrap();
    assert_eq!(session.phase, "complete");

    let paths = gitp2p_mesh::inspect_sync_path(&app_a, Some(&session.id)).unwrap();
    assert!(!paths.is_empty());
}
