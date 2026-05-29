use std::fs;
use std::path::PathBuf;
use std::process::Command;

use gitp2p_sync::{discover_filesystem, sync_to_peer};
use gitp2p_trust::write_peer;
use gitp2p_vault::{add_repo, create_checkpoint, create_vault, App};

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
fn two_peer_filesystem_sync() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-v2-{}",
        gitp2p_metadata::util::stable_id("lan-sync")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let home_a = root.join("home-a");
    let home_b = root.join("home-b");
    let repo = root.join("repo");
    init_repo(&repo);
    fs::write(repo.join("main.rs"), "fn main() {}\n").unwrap();
    run_git(&["add", "main.rs"], &repo);
    run_git(&["commit", "-m", "init"], &repo);

    let app_a = App::with_home(home_a.clone());
    app_a.ensure_home().unwrap();
    app_a.ensure_identity().unwrap();
    create_vault(&app_a, "team").unwrap();
    let vault = app_a.find_vault("team").unwrap();
    add_repo(&app_a, &vault, Some(repo.to_string_lossy().into()), "trusted").unwrap();

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
