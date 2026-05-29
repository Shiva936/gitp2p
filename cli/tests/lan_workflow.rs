use gitp2p_sync::sync::{discover_filesystem, sync_to_peer};
use gitp2p_core::trust::write_peer;
use gitp2p_core::{create_vault, App};
use gitp2p_testing::{commit_file, init_repo, temp_home};

#[test]
fn two_peer_filesystem_sync() {
    let root = temp_home("lan-sync");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();

    let home_a = root.join("home-a");
    let home_b = root.join("home-b");
    let repo = root.join("repo");
    init_repo(&repo);
    commit_file(&repo, "main.rs", "fn main() {}\n", "init");

    let app_a = App::with_home(home_a.clone());
    app_a.ensure_home().unwrap();
    app_a.ensure_identity().unwrap();
    create_vault(&app_a, "team").unwrap();
    let vault = app_a.find_vault("team").unwrap();
    gitp2p_core::add_repo(&app_a, &vault, Some(repo.to_string_lossy().into()), "trusted").unwrap();

    let app_b = App::with_home(home_b.clone());
    app_b.ensure_home().unwrap();
    app_b.ensure_identity().unwrap();

    let discovered = discover_filesystem(&app_a, &[home_b.clone()]).unwrap();
    assert!(!discovered.is_empty());
    let mut peer = discovered[0].clone();
    peer.trust_state = "trusted".into();
    write_peer(&app_a.home, &peer).unwrap();

    let session = sync_to_peer(&app_a, Some("repo"), &peer.id, false, false).unwrap();
    assert_eq!(session.phase, "complete");
}
