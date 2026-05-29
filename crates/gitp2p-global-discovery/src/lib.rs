use std::path::{Path, PathBuf};

use gitp2p_federation::{discovery_root, list_domains};
use gitp2p_gateway::{list_gateways, read_exchanged_routes};
use gitp2p_metadata::{optional_field, read_kv, write_kv, FederationDomain, Gateway, Result};
use gitp2p_metadata::util::{create_dir_all, timestamp};
use gitp2p_peering::list_peerings;
use gitp2p_vault::App;

#[derive(Clone, Debug)]
pub struct DiscoveryEntry {
    pub id: String,
    pub kind: String,
    pub source: String,
}

fn cache_dir(home: &Path, kind: &str) -> PathBuf {
    discovery_root(home).join(kind)
}

fn write_cache(home: &Path, kind: &str, id: &str, source: &str) -> Result<()> {
    let dir = cache_dir(home, kind);
    create_dir_all(&dir)?;
    write_kv(
        &dir.join(id),
        &[
            ("id", id),
            ("kind", kind),
            ("source", source),
            ("discovered_at", &timestamp()),
        ],
    )
}

fn read_cache(home: &Path, kind: &str) -> Result<Vec<DiscoveryEntry>> {
    let dir = cache_dir(home, kind);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let map = read_kv(&entry?.path())?;
        entries.push(DiscoveryEntry {
            id: optional_field(&map, "id"),
            kind: optional_field(&map, "kind"),
            source: optional_field(&map, "source"),
        });
    }
    Ok(entries)
}

pub fn discover_domains(app: &App) -> Result<Vec<FederationDomain>> {
    let mut domains = list_domains(app)?;
    for peering in list_peerings(app)? {
        if peering.state == "active" {
            write_cache(
                &app.home,
                "domains",
                &peering.remote_domain_id,
                "peering",
            )?;
            domains.push(FederationDomain {
                id: peering.remote_domain_id.clone(),
                name: peering.remote_domain_id.clone(),
                owner_peer_id: String::new(),
                trust_policy: "remote".into(),
                routing_policy: "gateway".into(),
                peering_policy: "peered".into(),
                created_at: peering.created_at.clone(),
                signature: peering.signature.clone(),
                signed_by: peering.signed_by.clone(),
                signed_at: peering.signed_at.clone(),
            });
        }
    }
    domains.sort_by(|a, b| a.id.cmp(&b.id));
    domains.dedup_by(|a, b| a.id == b.id);
    Ok(domains)
}

pub fn discover_gateways(app: &App) -> Result<Vec<Gateway>> {
    let mut gateways = list_gateways(app)?;
    let mut discovered = Vec::new();
    for gateway in &gateways {
        write_cache(&app.home, "gateways", &gateway.id, "local")?;
        for (remote, _) in read_exchanged_routes(&app.home, &gateway.id)? {
            if !remote.is_empty() {
                write_cache(&app.home, "gateways", &remote, "exchange")?;
                discovered.push(Gateway {
                    id: remote.clone(),
                    domain_id: "remote".into(),
                    listen_addr: "0.0.0.0".into(),
                    listen_port: 8443,
                    state: "discovered".into(),
                    created_at: timestamp(),
                    signature: String::new(),
                    signed_by: String::new(),
                    signed_at: String::new(),
                });
            }
        }
    }
    gateways.extend(discovered);
    gateways.sort_by(|a, b| a.id.cmp(&b.id));
    gateways.dedup_by(|a, b| a.id == b.id);
    Ok(gateways)
}

pub fn discover_vaults(app: &App) -> Result<Vec<DiscoveryEntry>> {
    let mut entries = Vec::new();
    for vault in app.all_vaults()? {
        write_cache(&app.home, "vaults", &vault.id, "local")?;
        entries.push(DiscoveryEntry {
            id: vault.id.clone(),
            kind: "vault".into(),
            source: "local".into(),
        });
    }
    entries.extend(read_cache(&app.home, "vaults")?);
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries.dedup_by(|a, b| a.id == b.id);
    Ok(entries)
}

pub fn discover_replicas(app: &App, repo_id: Option<&str>) -> Result<Vec<DiscoveryEntry>> {
    let mut entries = Vec::new();
    for vault in app.all_vaults()? {
        let dir = vault.path.join("replication");
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(dir)? {
            let map = read_kv(&entry?.path())?;
            let rid = optional_field(&map, "repo_id");
            if repo_id.is_some_and(|r| r != rid) {
                continue;
            }
            let peer = optional_field(&map, "peer_id");
            let cp = optional_field(&map, "checkpoint_id");
            let id = format!("{peer}-{rid}-{cp}");
            write_cache(&app.home, "replicas", &id, &peer)?;
            entries.push(DiscoveryEntry {
                id,
                kind: "replica".into(),
                source: peer,
            });
        }
    }
    for peering in list_peerings(app)? {
        if peering.state == "active" {
            let id = format!("{}-{}", peering.remote_domain_id, repo_id.unwrap_or("any"));
            write_cache(&app.home, "replicas", &id, "remote-domain")?;
            entries.push(DiscoveryEntry {
                id,
                kind: "replica".into(),
                source: peering.remote_domain_id.clone(),
            });
        }
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    entries.dedup_by(|a, b| a.id == b.id);
    Ok(entries)
}
