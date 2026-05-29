use std::path::Path;

use gitp2p_cas::{cas_root, chunk_id, load_chunk, store_chunk};
use gitp2p_metadata::Result;

pub fn delta_missing_chunks(home: &Path, local: &[u8], remote: &[u8]) -> Result<Vec<String>> {
    let local_id = chunk_id(local);
    let remote_id = chunk_id(remote);
    if local_id == remote_id {
        return Ok(Vec::new());
    }
    Ok(vec![remote_id])
}

pub fn propagate_missing(home: &Path, missing_ids: &[&str]) -> Result<Vec<Vec<u8>>> {
    let root = cas_root(home);
    missing_ids
        .iter()
        .map(|id| load_chunk(&root, id))
        .collect()
}

pub fn store_and_delta(home: &Path, content: &[u8]) -> Result<(String, Vec<String>)> {
    let root = cas_root(home);
    let id = store_chunk(&root, content)?;
    Ok((id, Vec::new()))
}
