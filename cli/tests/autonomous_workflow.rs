use gitp2p_runtime::{automation_pause, automation_tick};
use gitp2p_runtime::policy::create_policy;
use gitp2p_sync::sync::{discover_filesystem, sync_to_peer};
use gitp2p_core::trust::write_peer;
use gitp2p_core::{create_checkpoint, create_vault, App};
use gitp2p_testing::{commit_file, init_repo, temp_home};

#[test]
fn autonomous_workflow() {
    let root = temp_home("v6-auto");
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
    let repo_record = app_a.all_repos().unwrap().pop().unwrap();
    create_checkpoint(&app_a, Some(&repo_record.id), true, false, false).unwrap();

    let app_b = App::with_home(home_b.clone());
    app_b.ensure_home().unwrap();
    app_b.ensure_identity().unwrap();
    create_vault(&app_b, "team").unwrap();

    let discovered = discover_filesystem(&app_a, &[home_b.clone()]).unwrap();
    assert!(!discovered.is_empty());
    let mut peer = discovered[0].clone();
    peer.trust_state = "trusted".into();
    write_peer(&app_a.home, &peer).unwrap();

    create_policy(&app_a, "replica-policy", "replica", "team", "min_replicas=2").unwrap();
    create_policy(&app_a, "checkpoint-policy", "checkpoint", "team", "checkpoint_interval_hours=4").unwrap();

    let report = automation_tick(&app_a, "team", false).unwrap();
    assert!(!report.paused);
    assert!(!report.decisions.is_empty());

    automation_pause(&app_a).unwrap();
    let paused = automation_tick(&app_a, "team", false).unwrap();
    assert!(paused.paused);
    assert!(paused.decisions.is_empty());

    let health = gitp2p_runtime::calculate_health(&app_a, "team").unwrap();
    assert!(health.sync_score > 0);

    let history = gitp2p_runtime::explain::inspect_history(&app_a).unwrap();
    assert!(!history.is_empty());

    let _session = sync_to_peer(&app_a, Some(&repo_record.id), &peer.id, false, true).unwrap();
}
