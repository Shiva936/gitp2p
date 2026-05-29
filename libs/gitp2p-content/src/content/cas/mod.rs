use std::fs;
use std::path::{Path, PathBuf};

use gitp2p_core::{AppError, Result};
use gitp2p_core::util::create_dir_all;
use sha2::{Digest, Sha256};

pub fn chunk_id(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    format!("chunk-{}", hex_encode(&digest))
}

pub fn store_chunk(cas_root: &Path, content: &[u8]) -> Result<String> {
    let id = chunk_id(content);
    let path = chunk_path(cas_root, &id);
    if path.exists() {
        return Ok(id);
    }
    create_dir_all(path.parent().unwrap())?;
    fs::write(&path, content)?;
    Ok(id)
}

pub fn load_chunk(cas_root: &Path, id: &str) -> Result<Vec<u8>> {
    let path = chunk_path(cas_root, id);
    if !path.exists() {
        return Err(AppError::new(format!("chunk '{id}' not found")));
    }
    Ok(fs::read(path)?)
}

pub fn verify_chunk(cas_root: &Path, id: &str) -> Result<()> {
    let content = load_chunk(cas_root, id)?;
    let expected = chunk_id(&content);
    if expected != id {
        return Err(AppError::new(format!(
            "chunk content mismatch for {id}"
        )));
    }
    Ok(())
}

pub fn cas_root(home: &Path) -> PathBuf {
    home.join("cas")
}

fn chunk_path(cas_root: &Path, id: &str) -> PathBuf {
    let prefix = &id[6..8.min(id.len())];
    cas_root.join(prefix).join(id)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
