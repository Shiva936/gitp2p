use std::path::PathBuf;

use gitp2p_core::{add_repo, create_vault, App};

use crate::git::{commit_file, init_repo};

pub fn temp_home(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gitp2p-test-{}",
        gitp2p_core::util::stable_id(suffix)
    ))
}

pub fn temp_home_with_repo(suffix: &str) -> (PathBuf, PathBuf) {
    let home = temp_home(suffix);
    let _ = std::fs::remove_dir_all(&home);
    let repo = home.join("repo");
    init_repo(&repo);
    commit_file(&repo, "main.rs", "fn main() {}\n", "init");
    (home, repo)
}

pub fn setup_vault_with_repo(suffix: &str) -> App {
    let (home, repo) = temp_home_with_repo(suffix);
    let app = App::with_home(home);
    app.ensure_home().unwrap();
    app.ensure_identity().unwrap();
    create_vault(&app, "team").unwrap();
    let vault = app.find_vault("team").unwrap();
    add_repo(
        &app,
        &vault,
        Some(repo.to_string_lossy().into()),
        "trusted",
    )
    .unwrap();
    app
}
