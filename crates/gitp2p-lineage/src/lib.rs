use gitp2p_metadata::{Checkpoint, Result};
use gitp2p_vault::{checkpoint_lineage, App};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct LineageNode {
    pub id: String,
    pub parent: String,
    pub origin: String,
    pub kind: String,
}

pub fn build_lineage_chain(app: &App, checkpoint: &Checkpoint) -> Result<String> {
    checkpoint_lineage(app, checkpoint)
}

pub fn lineage_hash(chain: &str) -> String {
    let digest = Sha256::digest(chain.as_bytes());
    format!("lh-{}", hex_encode(&digest))
}

pub fn verify_lineage_hash(chain: &str, expected: &str) -> Result<()> {
    let actual = lineage_hash(chain);
    if actual != expected {
        return Err(gitp2p_metadata::AppError::new(format!(
            "lineage hash mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

pub fn inspect_lineage(app: &App, checkpoint_id: &str) -> Result<(String, String)> {
    let (_, _, checkpoint) = app.find_checkpoint(checkpoint_id)?;
    let chain = build_lineage_chain(app, &checkpoint)?;
    let hash = lineage_hash(&chain);
    Ok((chain, hash))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
