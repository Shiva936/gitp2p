use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use gitp2p_core::{read_kv, write_kv, Result};
use gitp2p_core::util::{create_dir_all, timestamp};
use sha2::{Digest, Sha256};

pub const MANIFEST_VERSION: &str = "3.0";

#[derive(Clone, Debug)]
pub struct FederationManifest {
    pub version: String,
    pub repo_id: String,
    pub checkpoint_id: String,
    pub lineage: String,
    pub lineage_hash: String,
    pub trust_zone: String,
    pub created_at: String,
}

impl FederationManifest {
    pub fn fields(&self) -> Vec<(&str, &str)> {
        vec![
            ("version", &self.version),
            ("repo_id", &self.repo_id),
            ("checkpoint_id", &self.checkpoint_id),
            ("lineage", &self.lineage),
            ("lineage_hash", &self.lineage_hash),
            ("trust_zone", &self.trust_zone),
            ("created_at", &self.created_at),
        ]
    }
}

pub fn manifest_hash(manifest: &FederationManifest) -> String {
    let canonical = canonical_manifest(manifest);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("mf-{}", hex_encode(&digest))
}

pub fn canonical_manifest(manifest: &FederationManifest) -> String {
    let mut parts = BTreeMap::new();
    for (k, v) in manifest.fields() {
        parts.insert(k, v);
    }
    parts
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn write_manifest(path: &Path, manifest: &FederationManifest) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut fields = manifest.fields();
    let hash = manifest_hash(manifest);
    fields.push(("manifest_hash", &hash));
    write_kv(path, &fields)
}

pub fn read_manifest(path: &Path) -> Result<FederationManifest> {
    let map = read_kv(path)?;
    Ok(FederationManifest {
        version: gitp2p_core::optional_field(&map, "version"),
        repo_id: gitp2p_core::optional_field(&map, "repo_id"),
        checkpoint_id: gitp2p_core::optional_field(&map, "checkpoint_id"),
        lineage: gitp2p_core::optional_field(&map, "lineage"),
        lineage_hash: gitp2p_core::optional_field(&map, "lineage_hash"),
        trust_zone: gitp2p_core::optional_field(&map, "trust_zone"),
        created_at: gitp2p_core::optional_field(&map, "created_at"),
    })
}

pub fn verify_manifest(path: &Path) -> Result<String> {
    let manifest = read_manifest(path)?;
    let expected = gitp2p_core::optional_field(&read_kv(path)?, "manifest_hash");
    let actual = manifest_hash(&manifest);
    if !expected.is_empty() && expected != actual {
        return Err(gitp2p_core::AppError::new(format!(
            "manifest hash mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(actual)
}

pub fn bundle_layout(root: &Path) -> BundleLayout {
    BundleLayout {
        root: root.to_path_buf(),
        repository_deltas: root.join("repository-deltas"),
        checkpoints: root.join("checkpoints"),
        lineage: root.join("lineage"),
        trust: root.join("trust"),
        manifest: root.join("manifest.json"),
    }
}

pub struct BundleLayout {
    pub root: PathBuf,
    pub repository_deltas: PathBuf,
    pub checkpoints: PathBuf,
    pub lineage: PathBuf,
    pub trust: PathBuf,
    pub manifest: PathBuf,
}

impl BundleLayout {
    pub fn ensure(&self) -> Result<()> {
        for dir in [
            &self.root,
            &self.repository_deltas,
            &self.checkpoints,
            &self.lineage,
            &self.trust,
        ] {
            create_dir_all(dir)?;
        }
        Ok(())
    }
}

pub fn new_manifest(
    repo_id: &str,
    checkpoint_id: &str,
    lineage: &str,
    lineage_hash: &str,
    trust_zone: &str,
) -> FederationManifest {
    FederationManifest {
        version: MANIFEST_VERSION.into(),
        repo_id: repo_id.into(),
        checkpoint_id: checkpoint_id.into(),
        lineage: lineage.into(),
        lineage_hash: lineage_hash.into(),
        trust_zone: trust_zone.into(),
        created_at: timestamp(),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
