use std::path::{Path, PathBuf};

use gitp2p_metadata::util::{create_dir_all, timestamp};

pub fn federation_root(home: &Path) -> PathBuf {
    home.join("federation")
}

pub fn domains_dir(home: &Path) -> PathBuf {
    federation_root(home).join("domains")
}

pub fn gateways_dir(home: &Path) -> PathBuf {
    federation_root(home).join("gateways")
}

pub fn peering_dir(home: &Path) -> PathBuf {
    federation_root(home).join("peering")
}

pub fn delegations_dir(home: &Path) -> PathBuf {
    federation_root(home).join("delegations")
}

pub fn discovery_root(home: &Path) -> PathBuf {
    home.join("discovery")
}

pub fn global_routing_dir(home: &Path) -> PathBuf {
    home.join("routing").join("global")
}

pub fn ensure_federation_layout(home: &Path) -> gitp2p_metadata::Result<()> {
    for dir in [
        domains_dir(home),
        gateways_dir(home),
        peering_dir(home),
        delegations_dir(home),
        discovery_root(home).join("domains"),
        discovery_root(home).join("gateways"),
        discovery_root(home).join("vaults"),
        discovery_root(home).join("replicas"),
        global_routing_dir(home),
    ] {
        create_dir_all(dir)?;
    }
    Ok(())
}

pub fn exchange_dir(home: &Path, gateway_id: &str) -> PathBuf {
    gateways_dir(home).join(gateway_id).join("exchange")
}

pub fn write_exchange_manifest(
    home: &Path,
    gateway_id: &str,
    kind: &str,
    name: &str,
    fields: &[(&str, &str)],
) -> gitp2p_metadata::Result<()> {
    let dir = exchange_dir(home, gateway_id).join(kind);
    create_dir_all(&dir)?;
    let mut all = fields.to_vec();
    let updated_at = timestamp();
    all.push(("updated_at", updated_at.as_str()));
    gitp2p_metadata::write_kv(&dir.join(name), &all)
}
