use std::fs;
use std::path::PathBuf;
use std::process::Command;

use gitp2p_bundle::{create_structured_bundle, validate_bundle, ExportOptions, export_bundle};
use gitp2p_manifest::verify_manifest;
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
    run_git(&["config", "user.email", "b@example.com"], path);
    run_git(&["config", "user.name", "B"], path);
}

#[test]
fn structured_bundle_roundtrip() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-v3-{}",
        gitp2p_metadata::util::stable_id("bundle")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let home = root.join("home");
    let repo_path = root.join("repo");
    init_repo(&repo_path);
    fs::write(repo_path.join("lib.rs"), "pub fn ok() {}\n").unwrap();
    run_git(&["add", "lib.rs"], &repo_path);
    run_git(&["commit", "-m", "init"], &repo_path);

    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();
    create_vault(&app, "offline").unwrap();
    let vault = app.find_vault("offline").unwrap();
    add_repo(
        &app,
        &vault,
        Some(repo_path.to_string_lossy().into()),
        "trusted",
    )
    .unwrap();
    create_checkpoint(&app, Some("repo"), false, false, false).unwrap();
    let repo = app.find_repo(Some("repo")).unwrap();

    let result = create_structured_bundle(&app, &repo, None, false).unwrap();
    verify_manifest(&result.manifest).unwrap();

    let bundle_file = result
        .bundle
        .join("repository-deltas")
        .join(format!("{}.bundle", repo.id));
    validate_bundle(&bundle_file).unwrap();
}

#[test]
fn incremental_bundle_export() {
    let root = std::env::temp_dir().join(format!(
        "gitp2p-v3-inc-{}",
        gitp2p_metadata::util::stable_id("inc")
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    let home = root.join("home");
    let repo_path = root.join("repo");
    init_repo(&repo_path);
    fs::write(repo_path.join("a.txt"), "a\n").unwrap();
    run_git(&["add", "a.txt"], &repo_path);
    run_git(&["commit", "-m", "a"], &repo_path);

    let app = App::with_home(home);
    app.ensure_home().unwrap();
    create_vault(&app, "v").unwrap();
    let vault = app.find_vault("v").unwrap();
    add_repo(
        &app,
        &vault,
        Some(repo_path.to_string_lossy().into()),
        "trusted",
    )
    .unwrap();
    let cp1 = create_checkpoint(&app, Some("repo"), false, false, false).unwrap();
    fs::write(repo_path.join("b.txt"), "b\n").unwrap();
    run_git(&["add", "b.txt"], &repo_path);
    run_git(&["commit", "-m", "b"], &repo_path);
    create_checkpoint(&app, Some("repo"), false, false, false).unwrap();
    let repo = app.find_repo(Some("repo")).unwrap();

    let result = export_bundle(
        &app,
        &repo,
        ExportOptions {
            since_checkpoint: Some(cp1.id),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(result.incremental);
    validate_bundle(&result.bundle).unwrap();
}
