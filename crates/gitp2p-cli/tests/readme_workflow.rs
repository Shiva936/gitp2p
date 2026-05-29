use std::fs;
use std::path::PathBuf;
use std::process::Command;

use gitp2p_metadata::RepoAction;
use gitp2p_recovery::recover_local;
use gitp2p_trust::enforce_repo_action;
use gitp2p_vault::{add_repo, create_checkpoint, create_vault, App};

fn run_git(args: &[&str], cwd: &PathBuf) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .expect("git should run");
    assert!(status.success(), "git {:?} failed in {}", args, cwd.display());
}

fn init_repo(path: &PathBuf) {
    fs::create_dir_all(path).unwrap();
    run_git(&["init"], path);
    run_git(&["config", "user.email", "test@example.com"], path);
    run_git(&["config", "user.name", "Test"], path);
}

#[test]
fn readme_quick_start_flow() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-it-{}",
        gitp2p_metadata::util::stable_id("readme-flow")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let home = root.join("home");
    let repo = root.join("repo");
    init_repo(&repo);
    fs::write(repo.join("README.md"), "hello gitp2p\n").unwrap();
    run_git(&["add", "README.md"], &repo);
    run_git(&["commit", "-m", "init"], &repo);

    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();
    create_vault(&app, "aeva").unwrap();
    let vault = app.find_vault("aeva").unwrap();
    add_repo(&app, &vault, Some(repo.to_string_lossy().into()), "trusted").unwrap();
    create_checkpoint(&app, Some("repo"), false, false, false).unwrap();
    let repo_record = app.find_repo(Some("repo")).unwrap();
    let recovered = root.join("recovered-aeva");
    recover_local(&app, &repo_record, None, Some(recovered.clone()), false).unwrap();
    assert!(recovered.join("README.md").exists());
}

#[test]
fn trust_zone_blocks_quarantined_export() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-it-{}",
        gitp2p_metadata::util::stable_id("quarantine")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let home = root.join("home");
    let repo = root.join("repo");
    init_repo(&repo);
    fs::write(repo.join("file.txt"), "x").unwrap();
    run_git(&["add", "file.txt"], &repo);
    run_git(&["commit", "-m", "init"], &repo);

    let app = App::with_home(home);
    app.ensure_home().unwrap();
    create_vault(&app, "vault").unwrap();
    let vault = app.find_vault("vault").unwrap();
    let repo_record = add_repo(
        &app,
        &vault,
        Some(repo.to_string_lossy().into()),
        "quarantined",
    )
    .unwrap();
    assert!(enforce_repo_action(&repo_record, RepoAction::Export, false, false).is_err());
}
