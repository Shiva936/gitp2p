use std::path::Path;

use gitp2p_metadata::git::git_fsck_ok;
use gitp2p_metadata::{Repo, Result};

pub struct DoctorReport {
    pub healthy: bool,
    pub message: String,
}

pub fn doctor_repo(repo: &Repo) -> Result<DoctorReport> {
    if !repo.path.exists() {
        return Ok(DoctorReport {
            healthy: false,
            message: format!(
                "working tree '{}' does not exist; run `gitp2p recover {}`",
                repo.path.display(),
                repo.name
            ),
        });
    }
    if git_fsck_ok(&repo.path)? {
        return Ok(DoctorReport {
            healthy: true,
            message: "repository integrity verified".into(),
        });
    }
    Ok(DoctorReport {
        healthy: false,
        message: format!(
            "repository integrity check failed; run `gitp2p recover {} [--checkpoint <id>]`",
            repo.name
        ),
    })
}

pub fn working_tree_needs_recovery(repo: &Repo) -> Result<bool> {
    if !repo.path.exists() {
        return Ok(true);
    }
    Ok(!git_fsck_ok(&repo.path)?)
}

pub fn prepare_recovery_target(target: &Path) -> Result<()> {
    use gitp2p_metadata::util::compact_timestamp;
    use std::ffi::OsStr;
    use std::fs;

    if !target.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(target)?;
    if entries.next().is_none() {
        fs::remove_dir(target)?;
        return Ok(());
    }
    let backup = target.with_file_name(format!(
        "{}.gitp2p-recovery-backup-{}",
        target.file_name().and_then(OsStr::to_str).unwrap_or("repo"),
        compact_timestamp()
    ));
    fs::rename(target, &backup)?;
    println!("existing target moved aside");
    println!("  backup: {}", backup.display());
    Ok(())
}
