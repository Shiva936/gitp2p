use std::fs;
use std::path::Path;

use gitp2p_metadata::{AppError, Result};
use gitp2p_metadata::util::{create_dir_all, max_concurrent_syncs, timestamp};

pub struct SyncSlot {
    lock_path: std::path::PathBuf,
}

impl SyncSlot {
    pub fn acquire(home: &Path) -> Result<Self> {
        create_dir_all(home.join("sessions").join("locks"))?;
        let inflight = count_inflight(home)?;
        let max = max_concurrent_syncs();
        if inflight >= max {
            return Err(AppError::new(format!(
                "concurrent sync limit reached ({inflight}/{max}); retry later"
            )));
        }
        let lock_path = home
            .join("sessions")
            .join("locks")
            .join(format!("sync-{}", timestamp()));
        fs::write(&lock_path, timestamp())?;
        Ok(Self { lock_path })
    }
}

impl Drop for SyncSlot {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn count_inflight(home: &Path) -> Result<usize> {
    let dir = home.join("sessions").join("locks");
    if !dir.exists() {
        return Ok(0);
    }
    Ok(fs::read_dir(dir)?.count())
}
