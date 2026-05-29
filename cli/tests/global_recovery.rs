use std::fs;
use std::path::PathBuf;
use std::process::Command;

use gitp2p_federation::create_domain;
use gitp2p_federation::create_gateway;
use gitp2p_federation::connect_domains;
use gitp2p_federation::discover_recovery_sources;
use gitp2p_core::{add_repo, create_checkpoint, create_vault, App};

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
fn global_recovery_sources() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-v5-recovery-{}",
        gitp2p_core::util::stable_id("global-recovery")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let home_a = root.join("home-a");
    let home_b = root.join("home-b");
    let repo_path = root.join("repo");
    init_repo(&repo_path);
    fs::write(repo_path.join("main.rs"), "fn main() {}\n").unwrap();
    run_git(&["add", "main.rs"], &repo_path);
    run_git(&["commit", "-m", "init"], &repo_path);

    let app_a = App::with_home(home_a.clone());
    app_a.ensure_home().unwrap();
    app_a.ensure_identity().unwrap();
    let domain_a = create_domain(&app_a, "domain-a").unwrap();
    let gw_a = create_gateway(&app_a, &domain_a.id, "127.0.0.1", 8443).unwrap();
    create_vault(&app_a, "team").unwrap();
    let vault = app_a.find_vault("team").unwrap();
    let repo = add_repo(&app_a, &vault, Some(repo_path.to_string_lossy().into()), "trusted").unwrap();
    create_checkpoint(&app_a, Some(&repo.id), false, false, false).unwrap();

    let app_b = App::with_home(home_b.clone());
    app_b.ensure_home().unwrap();
    app_b.ensure_identity().unwrap();
    let domain_b = create_domain(&app_b, "domain-b").unwrap();
    let gw_b = create_gateway(&app_b, &domain_b.id, "127.0.0.2", 8443).unwrap();
    connect_domains(
        &app_a,
        &domain_a.id,
        &domain_b.id,
        Some(&gw_a.id),
        Some(&gw_b.id),
    )
    .unwrap();

    let sources = discover_recovery_sources(&app_a, &repo.id).unwrap();
    assert!(!sources.is_empty());
}
