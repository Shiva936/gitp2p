use gitp2p_core::{Result};
use crate::relay_status;
use crate::inspect_routes;
use gitp2p_core::App;

pub fn topology_peers(app: &App) -> Result<String> {
    let mut out = String::from("peers:\n");
    for peer in app.all_peers()? {
        out.push_str(&format!(
            "  {} trust={} port={}\n",
            peer.id, peer.trust_state, peer.listen_port
        ));
    }
    Ok(out)
}

pub fn topology_routes(app: &App) -> Result<String> {
    let mut out = String::from("routes:\n");
    for route in inspect_routes(app)? {
        out.push_str(&format!(
            "  {} -> [{}] cost={}\n",
            route.destination,
            route.hops.join(" -> "),
            route.cost
        ));
    }
    Ok(out)
}

pub fn topology_vaults(app: &App) -> Result<String> {
    let mut out = String::from("vaults:\n");
    for vault in app.all_vaults()? {
        let replicas = gitp2p_core::util::count_files(vault.path.join("replication"))?;
        out.push_str(&format!("  {} replicas={replicas}\n", vault.name));
    }
    Ok(out)
}

pub fn topology_trust(app: &App) -> Result<String> {
    let mut out = String::from("trust:\n");
    for peer in app.all_peers()? {
        out.push_str(&format!("  {} -> {}\n", peer.id, peer.trust_state));
    }
    Ok(out)
}

pub fn topology_summary(app: &App) -> Result<String> {
    let relay = relay_status(app)?;
    Ok(format!(
        "{}{}{}\nrelay: enabled={} forwarded={}\n",
        topology_peers(app)?,
        topology_routes(app)?,
        topology_vaults(app)?,
        relay.enabled,
        relay.forwarded
    ))
}
