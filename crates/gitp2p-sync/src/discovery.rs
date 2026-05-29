use std::path::PathBuf;
use std::time::Duration;

use gitp2p_metadata::{Peer, Result};
use gitp2p_metadata::util::{listen_port, timestamp};
use gitp2p_trust::validate_peer_identity;
use gitp2p_trust::write_peer;
use gitp2p_vault::App;

pub fn discover_lan(app: &App, timeout_secs: u64) -> Result<Vec<Peer>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;
    runtime.block_on(discover_lan_async(app, timeout_secs))
}

async fn discover_lan_async(app: &App, timeout_secs: u64) -> Result<Vec<Peer>> {
    let service_type = "_gitp2p._tcp.local.";
    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;
    let receiver = mdns
        .browse(service_type)
        .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;

    let mut discovered = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(event)) => {
                if let mdns_sd::ServiceEvent::ServiceResolved(info) = event {
                    if let Some(peer) = peer_from_service(app, &info)? {
                        write_peer(&app.home, &peer)?;
                        discovered.push(peer);
                    }
                }
            }
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }

    mdns.shutdown().ok();
    Ok(discovered)
}

fn peer_from_service(
    app: &App,
    info: &mdns_sd::ServiceInfo,
) -> Result<Option<Peer>> {
    let props = info.get_properties();
    let peer_id = props
        .get("peer_id")
        .map(|v| v.val_str().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| gitp2p_metadata::AppError::new("mdns peer missing peer_id"))?;
    if peer_id == app.ensure_identity()?.peer_id {
        return Ok(None);
    }
    let public_key = props
        .get("public_key")
        .map(|v| v.val_str().to_string())
        .unwrap_or_default();
    validate_peer_identity(&public_key)?;
    let port = info.get_port();
    let trust_state = app
        .all_peers()?
        .into_iter()
        .find(|peer| peer.id == peer_id)
        .map(|peer| peer.trust_state)
        .unwrap_or_else(|| "untrusted".to_string());
    Ok(Some(Peer {
        id: peer_id,
        public_key,
        home: PathBuf::new(),
        trust_state,
        capabilities: "mdns,quic,filesystem".to_string(),
        vaults: props
            .get("vault_count")
            .map(|v| v.val_str().to_string())
            .unwrap_or_default(),
        discovered_at: timestamp(),
        listen_port: port,
    }))
}

pub fn advertise_lan(app: &App) -> Result<()> {
    listen_peers(app)
}

pub fn listen_peers(app: &App) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;
    runtime.block_on(listen_peers_async(app))
}

async fn listen_peers_async(app: &App) -> Result<()> {
    let identity = app.ensure_identity()?;
    let port = listen_port();
    let _tls = crate::tls::ensure_server_identity(&app.home)?;
    let mdns = mdns_sd::ServiceDaemon::new()
        .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;
    let host = hostname_local();
    let service_name = format!("{}._gitp2p._tcp.local.", identity.peer_id);
    let properties: std::collections::HashMap<String, String> = [
        ("peer_id", identity.peer_id.clone()),
        ("public_key", identity.public_key.clone()),
        ("fingerprint", identity.fingerprint.clone()),
        ("vault_count", app.all_vaults()?.len().to_string()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    let service = mdns_sd::ServiceInfo::new(
        "_gitp2p._tcp.local.",
        &service_name,
        &host,
        "",
        port,
        Some(properties),
    )
    .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;
    mdns.register(service)
        .map_err(|err| gitp2p_metadata::AppError::new(err.to_string()))?;

    let app_home = app.home.clone();
    let quic = tokio::spawn(async move {
        let listener_app = gitp2p_vault::App::with_home(app_home);
        if let Err(err) = crate::quic_server::run_quic_listener(&listener_app, port).await {
            eprintln!("quic listener stopped: {err}");
        }
    });

    println!("listening for LAN peers on port {port} (mDNS + QUIC); press Ctrl+C to stop");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = quic => {},
    }
    mdns.shutdown().ok();
    Ok(())
}

fn hostname_local() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "gitp2p.local".to_string())
}
