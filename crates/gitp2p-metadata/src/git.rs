use std::path::Path;
use std::process::Command;

use crate::error::{AppError, Result};

pub fn ensure_git_repo(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(AppError::new(format!(
            "path '{}' does not exist",
            path.display()
        )));
    }
    git(["rev-parse", "--git-dir"], Some(path)).map(|_| ())
}

pub fn git<const N: usize>(args: [&str; N], cwd: Option<&Path>) -> Result<()> {
    let output = git_command(args, cwd)?;
    if !output.status.success() {
        return Err(AppError::new(command_error("git", &output)));
    }
    Ok(())
}

pub fn git_output<const N: usize>(args: [&str; N], cwd: Option<&Path>) -> Result<String> {
    let output = git_command(args, cwd)?;
    if !output.status.success() {
        return Err(AppError::new(command_error("git", &output)));
    }
    Ok(String::from_utf8(output.stdout)?)
}

pub fn git_command<const N: usize>(
    args: [&str; N],
    cwd: Option<&Path>,
) -> Result<std::process::Output> {
    let mut cmd = Command::new("git");
    cmd.args(args);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    Ok(cmd.output()?)
}

pub fn git_fsck_ok(path: &Path) -> Result<bool> {
    match git_command(["fsck", "--full"], Some(path)) {
        Ok(output) => Ok(output.status.success()),
        Err(_) => Ok(false),
    }
}

fn command_error(program: &str, output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    format!("{program} failed: {detail}")
}
