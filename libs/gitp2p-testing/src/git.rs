use std::path::Path;
use std::process::Command;

pub fn run_git(args: &[&str], cwd: &Path) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .expect("git should run");
    assert!(status.success(), "git {:?} failed in {}", args, cwd.display());
}

pub fn init_repo(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    run_git(&["init"], path);
    run_git(&["config", "user.email", "a@example.com"], path);
    run_git(&["config", "user.name", "A"], path);
}

pub fn commit_file(repo: &Path, relative: &str, contents: &str, message: &str) {
    let file_path = repo.join(relative);
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&file_path, contents).unwrap();
    run_git(&["add", relative], repo);
    run_git(&["commit", "-m", message], repo);
}
