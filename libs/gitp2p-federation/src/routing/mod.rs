use std::collections::HashMap;
use std::path::Path;

use gitp2p_core::identity::federation_route_id;
use gitp2p_core::{field, optional_field, read_kv, write_kv, GlobalRoute, Peer, Result};
use gitp2p_core::util::timestamp;
use crate::global_routing_dir;
use crate::list_peerings;
use gitp2p_core::App;

#[derive(Clone, Debug)]
pub struct Route {
    pub destination: String,
    pub hops: Vec<String>,
    pub cost: u32,
}

pub fn discover_routes(app: &App, destination: &str) -> Result<Vec<Route>> {
    let mut routes = Vec::new();
    for peer in app.all_peers()? {
        if peer.trust_state == "trusted" || peer.trust_state == "readonly" {
            routes.push(Route {
                destination: destination.into(),
                hops: vec![peer.id.clone()],
                cost: 1,
            });
        }
    }
    Ok(routes)
}

pub fn select_route(routes: &[Route]) -> Option<Route> {
    routes.iter().min_by_key(|r| r.cost).cloned()
}

pub fn cache_route(home: &Path, route: &Route) -> Result<()> {
    let path = home.join("routing").join(format!("route-{}", route.destination));
    write_kv(
        &path,
        &[
            ("destination", &route.destination),
            ("hops", &route.hops.join(",")),
            ("cost", &route.cost.to_string()),
            ("updated_at", &timestamp()),
        ],
    )
}

pub fn inspect_routes(app: &App) -> Result<Vec<Route>> {
    let dir = app.home.join("routing");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut routes = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.parent().and_then(|p| p.file_name()).is_some_and(|n| n == "global") {
            continue;
        }
        let map = read_kv(&path)?;
        routes.push(Route {
            destination: optional_field(&map, "destination"),
            hops: optional_field(&map, "hops")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            cost: optional_field(&map, "cost").parse().unwrap_or(1),
        });
    }
    Ok(routes)
}

pub fn validate_route(route: &Route, peers: &[Peer]) -> Result<()> {
    let known: HashMap<_, _> = peers.iter().map(|p| (p.id.as_str(), p)).collect();
    for hop in &route.hops {
        if !known.contains_key(hop.as_str()) {
            return Err(gitp2p_core::AppError::new(format!(
                "unknown hop in route: {hop}"
            )));
        }
    }
    Ok(())
}

pub fn global_route_payload(route: &GlobalRoute) -> String {
    format!(
        "global-route:{}:{}:{}",
        route.destination, route.hops, route.gateway_hops
    )
}

pub fn read_global_route(path: &Path) -> Result<GlobalRoute> {
    let map = read_kv(path)?;
    Ok(GlobalRoute {
        id: field(&map, "id")?,
        destination: field(&map, "destination")?,
        hops: field(&map, "hops")?,
        gateway_hops: field(&map, "gateway_hops")?,
        cost: optional_field(&map, "cost").parse().unwrap_or(1),
        state: optional_field(&map, "state"),
        created_at: field(&map, "created_at")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_global_route(home: &Path, route: &GlobalRoute) -> Result<()> {
    gitp2p_core::util::create_dir_all(global_routing_dir(home))?;
    write_kv(
        &global_routing_dir(home).join(&route.id),
        &[
            ("id", &route.id),
            ("destination", &route.destination),
            ("hops", &route.hops),
            ("gateway_hops", &route.gateway_hops),
            ("cost", &route.cost.to_string()),
            ("state", &route.state),
            ("created_at", &route.created_at),
            ("signature", &route.signature),
            ("signed_by", &route.signed_by),
            ("signed_at", &route.signed_at),
        ],
    )
}

pub fn build_global_route(app: &App, destination: &str) -> Result<GlobalRoute> {
    let peerings = list_peerings(app)?;
    let local_domain = crate::local_domain(app)?
        .map(|d| d.id)
        .unwrap_or_else(|| "local".into());
    let gateway_hops: Vec<String> = peerings
        .iter()
        .filter(|p| p.state == "active")
        .map(|p| format!("{}->{}", p.local_gateway_id, p.remote_gateway_id))
        .collect();
    let hops = if gateway_hops.is_empty() {
        format!("peer->{local_domain}->{destination}")
    } else {
        format!(
            "peer->{local_domain}->{}->{}",
            gateway_hops.join("->"),
            destination
        )
    };
    let id = federation_route_id(destination, &hops);
    Ok(GlobalRoute {
        id,
        destination: destination.to_string(),
        hops: hops.clone(),
        gateway_hops: gateway_hops.join(","),
        cost: gateway_hops.len() as u32 + 2,
        state: "active".into(),
        created_at: timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    })
}

pub fn cache_global_route(app: &App, route: &GlobalRoute) -> Result<()> {
    write_global_route(&app.home, route)
}

pub fn inspect_global_routes(app: &App) -> Result<Vec<GlobalRoute>> {
    let dir = global_routing_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut routes = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        routes.push(read_global_route(&entry?.path())?);
    }
    Ok(routes)
}

pub fn verify_route(app: &App, route_id: &str) -> Result<GlobalRoute> {
    let route = inspect_global_routes(app)?
        .into_iter()
        .find(|r| r.id == route_id)
        .ok_or_else(|| gitp2p_core::AppError::new(format!("route '{route_id}' not found")))?;
    if route.state == "revoked" {
        return Err(gitp2p_core::AppError::new("route is revoked"));
    }
    let chain = gitp2p_core::trust::inspect_delegation_chain(&app.home, None)?;
    if !chain.is_empty() {
        let identity = app.ensure_identity()?;
        gitp2p_core::trust::validate_delegation_chain(&app.home, &identity, &chain)?;
    }
    Ok(route)
}

pub fn failover_route(app: &App, route_id: &str) -> Result<GlobalRoute> {
    let route = verify_route(app, route_id)?;
    let mut alternate = route.clone();
    alternate.id = federation_route_id(&route.destination, &format!("failover:{}", route.hops));
    alternate.state = "failover".into();
    alternate.cost = route.cost + 1;
    if !route.gateway_hops.is_empty() {
        let parts: Vec<_> = route.gateway_hops.split(',').collect();
        if parts.len() > 1 {
            alternate.gateway_hops = parts.into_iter().rev().collect::<Vec<_>>().join(",");
        }
    }
    alternate.hops = format!("failover:{}", route.hops);
    cache_global_route(app, &alternate)?;
    Ok(alternate)
}
