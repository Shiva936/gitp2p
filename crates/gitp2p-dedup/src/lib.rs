use std::collections::HashSet;
use std::path::Path;

use gitp2p_cas::{cas_root, chunk_id, store_chunk};
use gitp2p_metadata::Result;

pub fn deduplicate_store(home: &Path, content: &[u8]) -> Result<(String, bool)> {
    let root = cas_root(home);
    let id = chunk_id(content);
    let path = root.join(&id[6..8]).join(&id);
    let is_new = !path.exists();
    store_chunk(&root, content)?;
    Ok((id, is_new))
}

pub fn dedup_stats(home: &Path) -> Result<(usize, usize)> {
    let root = cas_root(home);
    if !root.exists() {
        return Ok((0, 0));
    }
    let mut unique = HashSet::new();
    let mut total = 0usize;
    walk(&root, &mut |path| {
        if path.is_file() {
            total += 1;
            if let Ok(data) = std::fs::read(path) {
                unique.insert(chunk_id(&data));
            }
        }
    })?;
    Ok((total, unique.len()))
}

fn walk(path: &Path, f: &mut dyn FnMut(&Path)) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            walk(&p, f)?;
        } else {
            f(&p);
        }
    }
    Ok(())
}
