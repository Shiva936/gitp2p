use std::collections::{HashMap, HashSet};
use std::path::Path;

use gitp2p_metadata::Result;

pub fn trust_graph(home: &Path, local_peer_id: &str) -> Result<HashMap<String, HashSet<String>>> {
    let mut graph: HashMap<String, HashSet<String>> = HashMap::new();
    let peers_dir = home.join("peers");
    if !peers_dir.exists() {
        return Ok(graph);
    }
    for entry in std::fs::read_dir(peers_dir)? {
        let peer = crate::read_peer(&entry?.path())?;
        if peer.trust_state == "trusted" || peer.trust_state == "readonly" {
            graph
                .entry(local_peer_id.to_string())
                .or_default()
                .insert(peer.id.clone());
        }
    }
    Ok(graph)
}

pub fn propagate_trust(home: &Path, from: &str, to: &str) -> Result<()> {
    let peer_path = home.join("peers").join(to);
    let mut peer = crate::read_peer(&peer_path)?;
    if peer.trust_state == "untrusted" {
        peer.trust_state = "pending".into();
    }
    gitp2p_metadata::write_kv(
        &home.join("trust-graph").join(format!("{from}-{to}")),
        &[
            ("from", from),
            ("to", to),
            ("state", &peer.trust_state),
            ("updated_at", &gitp2p_metadata::util::timestamp()),
        ],
    )?;
    crate::write_peer(home, &peer)
}

pub fn request_trust(home: &Path, peer_id: &str) -> Result<()> {
    let peer = crate::read_peer(&home.join("peers").join(peer_id))?;
    gitp2p_metadata::write_kv(
        &home.join("trust-requests").join(&peer.id),
        &[
            ("peer_id", &peer.id),
            ("public_key", &peer.public_key),
            ("state", "pending"),
            ("requested_at", &gitp2p_metadata::util::timestamp()),
        ],
    )
}

pub fn list_trust_requests(home: &Path) -> Result<Vec<String>> {
    let dir = home.join("trust-requests");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    Ok(std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect())
}

pub fn format_trust_graph(home: &Path, local_peer_id: &str) -> Result<String> {
    let graph = trust_graph(home, local_peer_id)?;
    let mut out = String::from("trust-graph:\n");
    for (from, peers) in graph {
        for to in peers {
            out.push_str(&format!("  {from} -> {to}\n"));
        }
    }
    Ok(out)
}
