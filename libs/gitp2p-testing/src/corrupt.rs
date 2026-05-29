use std::path::Path;

use gitp2p_content::{cas_root, store_chunk};
use gitp2p_core::{App, Vault};

pub fn corrupt_checkpoint_metadata(vault: &Vault, checkpoint_id: &str) -> gitp2p_core::Result<()> {
    let path = vault
        .path
        .join("metadata")
        .join("checkpoints")
        .join(checkpoint_id);
    let content = std::fs::read_to_string(&path)?;
    std::fs::write(path, format!("{content}\ncorrupted=true"))?;
    Ok(())
}

pub fn corrupt_cas_chunk(app: &App, chunk_id: &str) -> gitp2p_core::Result<()> {
    let prefix = &chunk_id[6..8.min(chunk_id.len())];
    let path = cas_root(&app.home).join(prefix).join(chunk_id);
    let mut data = std::fs::read(&path)?;
    if !data.is_empty() {
        data[0] ^= 0xff;
    }
    std::fs::write(path, data)?;
    Ok(())
}

pub fn corrupt_manifest(path: &Path) -> gitp2p_core::Result<()> {
    let content = std::fs::read_to_string(path)?;
    let corrupted = content.replace("checkpoint_id=", "checkpoint_id=corrupted-");
    std::fs::write(path, corrupted)?;
    Ok(())
}

pub fn truncate_repo_ref(repo_path: &Path) -> gitp2p_core::Result<()> {
    let head = std::fs::read_to_string(repo_path.join(".git/HEAD"))?;
    let ref_path = if let Some(branch) = head.strip_prefix("ref: refs/heads/") {
        repo_path.join(".git/refs/heads").join(branch.trim())
    } else {
        repo_path.join(".git/HEAD")
    };
    std::fs::write(ref_path, "0000000000000000000000000000000000000000")?;
    Ok(())
}

pub fn seed_cas_chunk(app: &App, data: &[u8]) -> gitp2p_core::Result<String> {
    store_chunk(&cas_root(&app.home), data)
}
