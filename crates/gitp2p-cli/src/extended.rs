use std::path::PathBuf;

use gitp2p_bundle::{
    create_structured_bundle, export_bundle, import_bundle, validate_bundle, ExportOptions,
};
use gitp2p_cas::{cas_root, store_chunk};
use gitp2p_dedup::dedup_stats;
use gitp2p_identity::{export_identity, import_identity, inspect_identity};
use gitp2p_lineage::inspect_lineage;
use gitp2p_manifest::{read_manifest, verify_manifest};
use gitp2p_media::{media_export, media_import};
use gitp2p_mesh::{mesh_sync, multi_hop_reconcile};
use gitp2p_merkle::merkle_root;
use gitp2p_portable_vault::{export_vault, import_vault};
use gitp2p_reconciliation::validate_reconciliation;
use gitp2p_relay::{relay_status, set_relay_enabled};
use gitp2p_routing::{discover_routes, inspect_routes, select_route};
use gitp2p_sync::replication_history;
use gitp2p_topology::{
    topology_peers, topology_routes, topology_summary, topology_trust, topology_vaults,
};
use gitp2p_trust::{format_trust_graph, list_trust_requests, request_trust};
use gitp2p_verify::{
    verify_checkpoint_full, verify_lineage, verify_manifest_file, verify_peer,
};
use gitp2p_vault::App;

pub fn cmd_bundle_create(
    app: &App,
    repo_ref: Option<String>,
    output: Option<PathBuf>,
    structured: bool,
    encrypt: bool,
    since: Option<String>,
) -> gitp2p_metadata::Result<()> {
    let repo = app.find_repo(repo_ref.as_deref())?;
    if structured {
        let result = create_structured_bundle(&app, &repo, output, encrypt)?;
        println!("structured bundle: {}", result.bundle.display());
        println!("  manifest: {}", result.manifest.display());
        return Ok(());
    }
    let result = export_bundle(
        app,
        &repo,
        ExportOptions {
            output,
            since_checkpoint: since,
            encrypt,
        },
    )?;
    println!("bundle exported: {}", result.bundle.display());
    Ok(())
}

pub fn cmd_bundle_validate(path: &PathBuf) -> gitp2p_metadata::Result<()> {
    validate_bundle(path)?;
    println!("bundle valid: {}", path.display());
    Ok(())
}

pub fn cmd_vault_export(
    app: &App,
    vault: &str,
    output: Option<PathBuf>,
) -> gitp2p_metadata::Result<()> {
    let result = export_vault(app, vault, output)?;
    println!("vault exported: {}", result.package.display());
    Ok(())
}

pub fn cmd_vault_import(
    app: &App,
    package: PathBuf,
    name: Option<String>,
) -> gitp2p_metadata::Result<()> {
    let vault = import_vault(app, &package, name.as_deref())?;
    println!("vault imported: {} ({})", vault.name, vault.id);
    Ok(())
}

pub fn cmd_lineage_inspect(app: &App, checkpoint_id: &str) -> gitp2p_metadata::Result<()> {
    let (chain, hash) = inspect_lineage(app, checkpoint_id)?;
    println!("lineage: {chain}");
    println!("lineage_hash: {hash}");
    Ok(())
}

pub fn cmd_manifest_inspect(path: &PathBuf) -> gitp2p_metadata::Result<()> {
    let manifest = read_manifest(path)?;
    for (k, v) in manifest.fields() {
        println!("{k}={v}");
    }
    Ok(())
}

pub fn cmd_manifest_verify(path: &PathBuf) -> gitp2p_metadata::Result<()> {
    let hash = verify_manifest(path)?;
    println!("manifest verified: {hash}");
    Ok(())
}

pub fn cmd_route_inspect(app: &App, destination: Option<String>) -> gitp2p_metadata::Result<()> {
    if let Some(dest) = destination {
        let routes = discover_routes(app, &dest)?;
        if let Some(route) = select_route(&routes) {
            println!("route: {} -> [{}]", route.destination, route.hops.join(" -> "));
        } else {
            println!("no route to {dest}");
        }
        return Ok(());
    }
    for route in inspect_routes(app)? {
        println!(
            "{} -> [{}] cost={}",
            route.destination,
            route.hops.join(" -> "),
            route.cost
        );
    }
    Ok(())
}

pub fn cmd_relay_status(app: &App) -> gitp2p_metadata::Result<()> {
    let state = relay_status(app)?;
    println!("relay enabled={} forwarded={}", state.enabled, state.forwarded);
    Ok(())
}

pub fn cmd_topology(app: &App, kind: &str) -> gitp2p_metadata::Result<()> {
    let out = match kind {
        "peers" => topology_peers(app)?,
        "routes" => topology_routes(app)?,
        "vaults" => topology_vaults(app)?,
        "trust" => topology_trust(app)?,
        _ => topology_summary(app)?,
    };
    print!("{out}");
    Ok(())
}

pub fn cmd_id_export(app: &App, dest: PathBuf) -> gitp2p_metadata::Result<()> {
    export_identity(&app.home, &dest)?;
    println!("identity exported: {}", dest.display());
    Ok(())
}

pub fn cmd_id_import(app: &App, source: PathBuf) -> gitp2p_metadata::Result<()> {
    let identity = import_identity(&app.home, &source)?;
    println!("identity imported: {}", identity.peer_id);
    Ok(())
}

pub fn cmd_peer_verify(app: &App, peer_id: &str) -> gitp2p_metadata::Result<()> {
    verify_peer(app, peer_id)?;
    println!("peer verified: {peer_id}");
    Ok(())
}

pub fn cmd_checkpoint_verify(app: &App, checkpoint_id: &str) -> gitp2p_metadata::Result<()> {
    verify_checkpoint_full(app, checkpoint_id)?;
    println!("checkpoint verified: {checkpoint_id}");
    Ok(())
}

pub fn cmd_merkle_verify(leaves: &[String]) -> gitp2p_metadata::Result<()> {
    let refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let root = merkle_root(&refs);
    println!("merkle_root: {root}");
    Ok(())
}

pub fn cmd_recover_offline(app: &App, bundle: PathBuf, vault: Option<String>) -> gitp2p_metadata::Result<()> {
    if bundle.join("manifest.json").exists() {
        validate_reconciliation(&bundle.join("manifest.json"))?;
    }
    let (vault, repo) = import_bundle(app, &bundle, vault.as_deref())?;
    println!("offline recovery complete");
    println!("  vault: {}", vault.name);
    println!("  repo: {} ({})", repo.name, repo.id);
    Ok(())
}

pub fn cmd_mesh_sync(
    app: &App,
    repo: Option<String>,
    destination: String,
    requires_approval: bool,
    enforce_retention: bool,
) -> gitp2p_metadata::Result<()> {
    let session = mesh_sync(
        app,
        repo.as_deref(),
        &destination,
        requires_approval,
        enforce_retention,
    )?;
    println!("mesh sync complete: {}", session.id);
    Ok(())
}

pub fn cmd_replication_history(app: &App, peer_id: Option<String>) -> gitp2p_metadata::Result<()> {
    for (peer, repo, history) in replication_history(app, peer_id.as_deref())? {
        println!("{peer}\t{repo}\t{history}");
    }
    Ok(())
}

pub fn cmd_trust_request(app: &App, peer_id: &str) -> gitp2p_metadata::Result<()> {
    request_trust(&app.home, peer_id)?;
    println!("trust request sent to {peer_id}");
    Ok(())
}

pub fn cmd_trust_graph(app: &App) -> gitp2p_metadata::Result<()> {
    let identity = app.ensure_identity()?;
    print!("{}", format_trust_graph(&app.home, &identity.peer_id)?);
    Ok(())
}

pub fn cmd_cas_store(app: &App, path: PathBuf) -> gitp2p_metadata::Result<()> {
    let data = std::fs::read(&path)?;
    let id = store_chunk(&cas_root(&app.home), &data)?;
    let (total, unique) = dedup_stats(&app.home)?;
    println!("chunk stored: {id} (files={total} unique={unique})");
    Ok(())
}

pub fn cmd_vault_join(app: &App, package: PathBuf) -> gitp2p_metadata::Result<()> {
    cmd_vault_import(app, package, None)
}

pub fn cmd_recover_network(
    app: &App,
    repo: &str,
    destination: &str,
) -> gitp2p_metadata::Result<()> {
    cmd_mesh_sync(app, Some(repo.into()), destination.into(), false, false)
}

pub fn cmd_lineage_verify(
    app: &App,
    checkpoint_id: &str,
    expected_hash: &str,
) -> gitp2p_metadata::Result<()> {
    verify_lineage(app, checkpoint_id, expected_hash)?;
    println!("lineage verified: {checkpoint_id}");
    Ok(())
}

pub fn cmd_manifest_verify_file(path: &PathBuf) -> gitp2p_metadata::Result<()> {
    verify_manifest_file(path)?;
    cmd_manifest_verify(path)
}

pub fn cmd_id_inspect(app: &App) -> gitp2p_metadata::Result<()> {
    let identity = inspect_identity(&app.home)?;
    println!("peer_id: {}", identity.peer_id);
    println!("fingerprint: {}", identity.fingerprint);
    Ok(())
}

pub fn cmd_multi_hop_reconcile(app: &App, repo_id: &str) -> gitp2p_metadata::Result<()> {
    let dups = multi_hop_reconcile(app, repo_id)?;
    if dups.is_empty() {
        println!("no duplicate propagation for {repo_id}");
    } else {
        println!("duplicate checkpoints: {}", dups.join(","));
    }
    Ok(())
}

pub fn cmd_media_export(source: PathBuf, media: PathBuf) -> gitp2p_metadata::Result<()> {
    let dest = media_export(&source, &media)?;
    println!("media export: {}", dest.display());
    Ok(())
}

pub fn cmd_media_import(media: PathBuf, name: String) -> gitp2p_metadata::Result<()> {
    let path = media_import(&media, &name)?;
    println!("media import: {}", path.display());
    Ok(())
}

pub fn cmd_trust_requests(app: &App) -> gitp2p_metadata::Result<()> {
    for peer in list_trust_requests(&app.home)? {
        println!("pending: {peer}");
    }
    Ok(())
}

pub fn cmd_domain_create(app: &App, name: &str) -> gitp2p_metadata::Result<()> {
    let domain = gitp2p_federation::create_domain(app, name)?;
    println!("domain created: {} ({})", domain.name, domain.id);
    Ok(())
}

pub fn cmd_domain_inspect(app: &App, reference: Option<String>) -> gitp2p_metadata::Result<()> {
    let domains = if let Some(ref_) = reference {
        vec![gitp2p_federation::find_domain(app, &ref_)?]
    } else {
        gitp2p_federation::list_domains(app)?
    };
    for domain in domains {
        println!(
            "{} name={} owner={} trust={} routing={} peering={}",
            domain.id,
            domain.name,
            domain.owner_peer_id,
            domain.trust_policy,
            domain.routing_policy,
            domain.peering_policy
        );
    }
    Ok(())
}

pub fn cmd_domain_policy_set(
    app: &App,
    reference: &str,
    field: &str,
    value: &str,
) -> gitp2p_metadata::Result<()> {
    let domain = gitp2p_federation::update_domain_policy(app, reference, field, value)?;
    println!("domain policy updated: {} {}={}", domain.id, field, value);
    Ok(())
}

pub fn cmd_domain_delete(app: &App, reference: &str, yes: bool) -> gitp2p_metadata::Result<()> {
    let domain = gitp2p_federation::remove_domain(app, reference, yes)?;
    println!("domain deleted: {}", domain.id);
    Ok(())
}

pub fn cmd_domain_migrate(
    app: &App,
    target: &str,
    vault: Option<String>,
) -> gitp2p_metadata::Result<()> {
    let report = gitp2p_mobility::migrate_domain(app, target, vault.as_deref())?;
    println!(
        "domain migrated: {} -> {} continuity={}",
        report.source_domain, report.target_domain, report.continuity_ok
    );
    Ok(())
}

pub fn cmd_gateway_create(
    app: &App,
    domain: Option<String>,
    listen: Option<String>,
) -> gitp2p_metadata::Result<()> {
    let domain = match domain {
        Some(id) => gitp2p_federation::find_domain(app, &id)?,
        None => gitp2p_federation::ensure_local_domain(app)?,
    };
    let addr = listen.unwrap_or_else(|| "0.0.0.0".into());
    let gateway = gitp2p_gateway::create_gateway(app, &domain.id, &addr, 8443)?;
    println!("gateway created: {} domain={}", gateway.id, gateway.domain_id);
    Ok(())
}

pub fn cmd_gateway_inspect(app: &App, reference: Option<String>) -> gitp2p_metadata::Result<()> {
    let gateways = if let Some(ref_) = reference {
        vec![gitp2p_gateway::find_gateway(app, &ref_)?]
    } else {
        gitp2p_gateway::list_gateways(app)?
    };
    for gateway in gateways {
        println!(
            "{} domain={} addr={}:{} state={}",
            gateway.id,
            gateway.domain_id,
            gateway.listen_addr,
            gateway.listen_port,
            gateway.state
        );
    }
    Ok(())
}

pub fn cmd_peer_domain_connect(
    app: &App,
    remote_domain: &str,
    gateway: Option<String>,
) -> gitp2p_metadata::Result<()> {
    let local = gitp2p_federation::ensure_local_domain(app)?;
    let peering = gitp2p_peering::connect_domains(
        app,
        &local.id,
        remote_domain,
        gateway.as_deref(),
        None,
    )?;
    println!("peering established: {}", peering.id);
    Ok(())
}

pub fn cmd_peer_domain_revoke(app: &App, remote_domain: &str) -> gitp2p_metadata::Result<()> {
    let peering = gitp2p_peering::revoke_peering(app, remote_domain)?;
    println!("peering revoked: {}", peering.id);
    Ok(())
}

pub fn cmd_peer_domain_inspect(
    app: &App,
    remote_domain: Option<String>,
) -> gitp2p_metadata::Result<()> {
    for peering in gitp2p_peering::inspect_peering(app, remote_domain.as_deref())? {
        println!(
            "{} local={} remote={} state={}",
            peering.id, peering.local_domain_id, peering.remote_domain_id, peering.state
        );
    }
    Ok(())
}

pub fn cmd_trust_delegate(
    app: &App,
    target: &str,
    delegation_type: &str,
    scope: &str,
) -> gitp2p_metadata::Result<()> {
    let identity = app.ensure_identity()?;
    let delegation = gitp2p_trust::create_delegation(
        &app.home,
        &identity,
        target,
        delegation_type,
        scope,
        None,
    )?;
    println!("delegation created: {}", delegation.id);
    Ok(())
}

pub fn cmd_trust_revoke_delegation(app: &App, id: &str) -> gitp2p_metadata::Result<()> {
    let identity = app.ensure_identity()?;
    let delegation = gitp2p_trust::revoke_delegation(&app.home, &identity, id)?;
    println!("delegation revoked: {}", delegation.id);
    Ok(())
}

pub fn cmd_trust_inspect_delegation(
    app: &App,
    chain: bool,
    root: Option<String>,
) -> gitp2p_metadata::Result<()> {
    let delegations = if chain {
        gitp2p_trust::inspect_delegation_chain(&app.home, root.as_deref())?
    } else {
        gitp2p_trust::list_delegations(&app.home)?
    };
    for delegation in delegations {
        println!(
            "{} {} -> {} type={} state={}",
            delegation.id,
            delegation.source_id,
            delegation.target_id,
            delegation.delegation_type,
            delegation.state
        );
    }
    Ok(())
}

pub fn cmd_discover(kind: &str, app: &App, repo: Option<String>) -> gitp2p_metadata::Result<()> {
    match kind {
        "domains" => {
            for domain in gitp2p_global_discovery::discover_domains(app)? {
                println!("{} name={}", domain.id, domain.name);
            }
        }
        "gateways" => {
            for gateway in gitp2p_global_discovery::discover_gateways(app)? {
                println!("{} domain={} state={}", gateway.id, gateway.domain_id, gateway.state);
            }
        }
        "vaults" => {
            for entry in gitp2p_global_discovery::discover_vaults(app)? {
                println!("{} source={}", entry.id, entry.source);
            }
        }
        "replicas" => {
            for entry in gitp2p_global_discovery::discover_replicas(app, repo.as_deref())? {
                println!("{} source={}", entry.id, entry.source);
            }
        }
        other => {
            return Err(gitp2p_metadata::AppError::new(format!(
                "unknown discovery kind '{other}'"
            )));
        }
    }
    Ok(())
}

pub fn cmd_route_verify(app: &App, route_id: &str) -> gitp2p_metadata::Result<()> {
    let route = gitp2p_routing::verify_route(app, route_id)?;
    println!("route verified: {} -> {}", route.id, route.destination);
    Ok(())
}

pub fn cmd_route_inspect_global(
    app: &App,
    destination: Option<String>,
    global: bool,
) -> gitp2p_metadata::Result<()> {
    if global {
        if let Some(dest) = destination {
            let route = gitp2p_routing::build_global_route(app, &dest)?;
            gitp2p_routing::cache_global_route(app, &route)?;
            println!("global route: {} hops={}", route.id, route.hops);
            return Ok(());
        }
        for route in gitp2p_routing::inspect_global_routes(app)? {
            println!("{} dest={} hops={} cost={}", route.id, route.destination, route.hops, route.cost);
        }
        return Ok(());
    }
    cmd_route_inspect(app, destination)
}

pub fn cmd_global_sync(
    app: &App,
    repo: Option<String>,
    domain: &str,
    requires_approval: bool,
    enforce_retention: bool,
) -> gitp2p_metadata::Result<()> {
    gitp2p_relay::set_relay_enabled(app, true)?;
    let session = gitp2p_mesh::global_sync(
        app,
        repo.as_deref(),
        domain,
        requires_approval,
        enforce_retention,
    )?;
    println!("global sync complete: {}", session.id);
    Ok(())
}

pub fn cmd_sync_inspect(app: &App, session_id: Option<String>) -> gitp2p_metadata::Result<()> {
    for path in gitp2p_mesh::inspect_sync_path(app, session_id.as_deref())? {
        println!(
            "{} repo={} route={} path={} phase={}",
            path.session_id, path.repo_id, path.route_id, path.path, path.phase
        );
    }
    Ok(())
}

pub fn cmd_recover_global(
    app: &App,
    repo: &str,
    domain: Option<String>,
    target: Option<PathBuf>,
) -> gitp2p_metadata::Result<()> {
    let repo = app.find_repo(Some(repo))?;
    gitp2p_recovery::recover_global(&app, &repo, domain.as_deref(), target)?;
    println!("global recovery complete: {}", repo.id);
    Ok(())
}

pub fn cmd_recover_sources(app: &App, repo: &str) -> gitp2p_metadata::Result<()> {
    let sources = gitp2p_recovery::recover_sources(&app, repo)?;
    print!("{}", gitp2p_recovery::format_recovery_sources(&sources));
    Ok(())
}

pub fn cmd_verify_v5(app: &App, kind: &str, id: &str) -> gitp2p_metadata::Result<()> {
    match kind {
        "domain" => gitp2p_verify::verify_domain_record(app, id)?,
        "gateway" => gitp2p_verify::verify_gateway_record(app, id)?,
        "peering" => gitp2p_verify::verify_peering_record(app, id)?,
        "delegation" => gitp2p_verify::verify_delegation_record(app, id)?,
        "route" => gitp2p_verify::verify_global_route(app, id)?,
        other => {
            return Err(gitp2p_metadata::AppError::new(format!(
                "unknown verify kind '{other}'"
            )));
        }
    }
    println!("{kind} verified: {id}");
    Ok(())
}
