use std::path::Path;

use crate::{field, optional_field, read_kv, write_kv, Peer, Result};

use crate::trust::identity::validate_peer_identity;

pub fn read_peer(path: &Path) -> Result<Peer> {
    let map = read_kv(path)?;
    Ok(Peer {
        id: field(&map, "id")?,
        public_key: field(&map, "public_key")?,
        home: field(&map, "home")?.into(),
        trust_state: field(&map, "trust_state")?,
        capabilities: field(&map, "capabilities")?,
        vaults: optional_field(&map, "vaults"),
        discovered_at: field(&map, "discovered_at")?,
        listen_port: optional_field(&map, "listen_port")
            .parse()
            .unwrap_or(9134),
    })
}

pub fn write_peer(home: &Path, peer: &Peer) -> Result<()> {
    write_kv(
        &home.join("peers").join(&peer.id),
        &[
            ("id", &peer.id),
            ("public_key", &peer.public_key),
            ("home", &peer.home.to_string_lossy()),
            ("trust_state", &peer.trust_state),
            ("capabilities", &peer.capabilities),
            ("vaults", &peer.vaults),
            ("discovered_at", &peer.discovered_at),
            ("listen_port", &peer.listen_port.to_string()),
        ],
    )
}

pub fn authorize_peer(peer: &Peer, requires_approval: bool) -> Result<()> {
    validate_peer_identity(&peer.public_key)?;
    match peer.trust_state.as_str() {
        "trusted" | "protected" => Ok(()),
        "readonly" if !requires_approval => Ok(()),
        "experimental" if requires_approval => Ok(()),
        state => Err(crate::AppError::new(format!(
            "peer '{}' is not authorized for synchronization (state: {state}); run trust add first",
            peer.id
        ))),
    }
}

pub fn peer_is_trusted(peer: &Peer) -> bool {
    matches!(peer.trust_state.as_str(), "trusted" | "protected")
}
