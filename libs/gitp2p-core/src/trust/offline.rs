use std::path::Path;

use crate::{read_kv, write_kv, Result};
use crate::trust::identity::validate_peer_identity;
use crate::trust::peer::read_peer;

pub fn export_trust_bundle(home: &Path, dest: &Path) -> Result<()> {
    crate::util::create_dir_all(dest)?;
    let peers_dir = home.join("peers");
    if peers_dir.exists() {
        for entry in std::fs::read_dir(peers_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let peer = read_peer(&entry.path())?;
                write_kv(
                    &dest.join(format!("peer-{}", peer.id)),
                    &[
                        ("id", &peer.id),
                        ("public_key", &peer.public_key),
                        ("trust_state", &peer.trust_state),
                        ("capabilities", &peer.capabilities),
                        ("vaults", &peer.vaults),
                        ("discovered_at", &peer.discovered_at),
                        ("listen_port", &peer.listen_port.to_string()),
                    ],
                )?;
            }
        }
    }
    let graph_dir = home.join("trust-graph");
    if graph_dir.exists() {
        let out = dest.join("trust-graph");
        crate::util::create_dir_all(&out)?;
        for entry in std::fs::read_dir(graph_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name();
                std::fs::copy(entry.path(), out.join(name))?;
            }
        }
    }
    write_kv(
        &dest.join("trust-manifest"),
        &[
            ("kind", "trust-bundle"),
            ("exported_at", &crate::metadata::util::timestamp()),
        ],
    )?;
    Ok(())
}

pub fn validate_trust_bundle(home: &Path, source: &Path) -> Result<()> {
    let manifest = source.join("trust-manifest");
    if !manifest.exists() {
        return Err(crate::AppError::new("missing trust-manifest in bundle"));
    }
    let map = read_kv(&manifest)?;
    if map.get("kind").map(String::as_str) != Some("trust-bundle") {
        return Err(crate::AppError::new("invalid trust bundle kind"));
    }
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("peer-") {
            continue;
        }
        let map = read_kv(&entry.path())?;
        let public_key = map
            .get("public_key")
            .ok_or_else(|| crate::AppError::new("peer record missing public_key"))?;
        validate_peer_identity(public_key)?;
        let trust_state = map.get("trust_state").map(String::as_str).unwrap_or("");
        if trust_state == "trusted" || trust_state == "readonly" {
            let _ = home;
        }
    }
    Ok(())
}
