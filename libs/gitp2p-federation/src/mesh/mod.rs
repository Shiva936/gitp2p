use gitp2p_core::{Result, Session, SyncPath};
use gitp2p_core::util::{create_dir_all, timestamp};
use crate::forward_propagation;
use crate::{build_global_route, cache_global_route, discover_routes, select_route, validate_route};
use crate::sync_forward;
use gitp2p_sync::sync::sync_to_peer;
use gitp2p_core::App;

pub fn mesh_sync(
    app: &App,
    repo_ref: Option<&str>,
    destination: &str,
    requires_approval: bool,
    enforce_retention: bool,
) -> Result<Session> {
    let routes = discover_routes(app, destination)?;
    let route = select_route(&routes).ok_or_else(|| {
        gitp2p_core::AppError::new(format!("no route to destination '{destination}'"))
    })?;
    validate_route(&route, &app.all_peers()?)?;
    let mut last_session = None;
    for hop in &route.hops {
        let session = sync_to_peer(
            app,
            repo_ref,
            hop,
            requires_approval,
            enforce_retention,
        )?;
        forward_propagation(app, &session.id, destination)?;
        last_session = Some(session);
    }
    last_session.ok_or_else(|| gitp2p_core::AppError::new("mesh sync produced no session"))
}

pub fn multi_hop_reconcile(app: &App, repo_id: &str) -> Result<Vec<String>> {
    let mut seen = std::collections::HashSet::new();
    let mut duplicates = Vec::new();
    for vault in app.all_vaults()? {
        let dir = vault.path.join("replication");
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(dir)? {
            let map = gitp2p_core::read_kv(&entry?.path())?;
            if gitp2p_core::optional_field(&map, "repo_id") != repo_id {
                continue;
            }
            let cp = gitp2p_core::optional_field(&map, "checkpoint_id");
            if !seen.insert(cp.clone()) {
                duplicates.push(cp);
            }
        }
    }
    Ok(duplicates)
}

pub fn write_sync_path(app: &App, path: &SyncPath) -> Result<()> {
    create_dir_all(app.home.join("sync").join("paths"))?;
    gitp2p_core::write_kv(
        &app.home.join("sync").join("paths").join(&path.session_id),
        &[
            ("session_id", &path.session_id),
            ("repo_id", &path.repo_id),
            ("route_id", &path.route_id),
            ("path", &path.path),
            ("phase", &path.phase),
            ("updated_at", &timestamp()),
        ],
    )
}

pub fn inspect_sync_path(app: &App, session_id: Option<&str>) -> Result<Vec<SyncPath>> {
    let dir = app.home.join("sync").join("paths");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let map = gitp2p_core::read_kv(&entry?.path())?;
        let sid = gitp2p_core::optional_field(&map, "session_id");
        if session_id.is_some_and(|s| s != sid) {
            continue;
        }
        paths.push(SyncPath {
            session_id: sid,
            repo_id: gitp2p_core::optional_field(&map, "repo_id"),
            route_id: gitp2p_core::optional_field(&map, "route_id"),
            path: gitp2p_core::optional_field(&map, "path"),
            phase: gitp2p_core::optional_field(&map, "phase"),
        });
    }
    Ok(paths)
}

pub fn global_sync(
    app: &App,
    repo_ref: Option<&str>,
    destination_domain: &str,
    requires_approval: bool,
    enforce_retention: bool,
) -> Result<Session> {
    let route = build_global_route(app, destination_domain)?;
    cache_global_route(app, &route)?;
    let repo = app.find_repo(repo_ref)?;

    let sync_target = {
        let routes = discover_routes(app, destination_domain)?;
        if let Some(selected) = select_route(&routes) {
            selected.hops[0].clone()
        } else {
            app.all_peers()?
                .into_iter()
                .find(|peer| peer.trust_state == "trusted" || peer.trust_state == "readonly")
                .map(|peer| peer.id)
                .ok_or_else(|| {
                    gitp2p_core::AppError::new(format!(
                        "no peer route for domain '{destination_domain}'"
                    ))
                })?
        }
    };

    let session = sync_to_peer(
        app,
        Some(&repo.id),
        &sync_target,
        requires_approval,
        enforce_retention,
    )?;

    for hop in route
        .gateway_hops
        .split(',')
        .flat_map(|segment| segment.split("->"))
        .filter(|hop| !hop.is_empty())
    {
        sync_forward(app, &session.id, hop)?;
    }

    write_sync_path(
        app,
        &SyncPath {
            session_id: session.id.clone(),
            repo_id: repo.id.clone(),
            route_id: route.id.clone(),
            path: route.hops.clone(),
            phase: session.phase.clone(),
        },
    )?;

    Ok(session)
}
