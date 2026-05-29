use sha2::{Digest, Sha256};

pub fn merkle_root(leaves: &[&str]) -> String {
    if leaves.is_empty() {
        return merkle_hash("");
    }
    let mut layer: Vec<String> = leaves.iter().map(|l| merkle_hash(l)).collect();
    while layer.len() > 1 {
        let mut next = Vec::new();
        let mut i = 0;
        while i < layer.len() {
            let left = &layer[i];
            let right = if i + 1 < layer.len() {
                &layer[i + 1]
            } else {
                left
            };
            next.push(merkle_hash(&format!("{left}{right}")));
            i += 2;
        }
        layer = next;
    }
    layer[0].clone()
}

pub fn verify_merkle_root(leaves: &[&str], expected: &str) -> gitp2p_core::Result<()> {
    let actual = merkle_root(leaves);
    if actual != expected {
        return Err(gitp2p_core::AppError::new(format!(
            "merkle root mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn merkle_hash(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    format!("mk-{}", hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_root_is_deterministic() {
        let leaves = vec!["a", "b", "c"];
        assert_eq!(merkle_root(&leaves), merkle_root(&leaves));
    }
}
