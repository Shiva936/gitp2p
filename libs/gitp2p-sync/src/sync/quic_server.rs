use std::path::{Path, PathBuf};

use gitp2p_core::{AppError, Result};
use gitp2p_core::util::{create_dir_all, timestamp};
use gitp2p_core::App;

pub async fn run_quic_listener(app: &App, port: u16) -> Result<()> {
    use quinn::Endpoint;

    let identity = crate::tls::ensure_server_identity(&app.home)?;
    let server_config = crate::tls::make_server_config(&identity)?;
    let addr = format!("0.0.0.0:{port}");
    let endpoint = Endpoint::server(server_config, addr.parse().unwrap())
        .map_err(|err| AppError::new(err.to_string()))?;

    let incoming_dir = app.home.join("sessions").join("incoming");
    create_dir_all(&incoming_dir)?;

    loop {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| AppError::new("quic listener closed"))?;
        let conn = incoming
            .await
            .map_err(|err| AppError::new(err.to_string()))?;
        let dir = incoming_dir.clone();
        tokio::spawn(async move {
            if let Err(err) = accept_bundle_stream(&conn, &dir).await {
                eprintln!("quic receive error: {err}");
            }
        });
    }
}

async fn accept_bundle_stream(
    connection: &quinn::Connection,
    incoming_dir: &Path,
) -> Result<()> {
    let (_send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|err| AppError::new(err.to_string()))?;
    let data = recv
        .read_to_end(256 * 1024 * 1024)
        .await
        .map_err(|err| AppError::new(err.to_string()))?;
    let path = incoming_dir.join(format!("incoming-{}.bundle", timestamp()));
    tokio::fs::write(&path, &data)
        .await
        .map_err(|err| AppError::new(err.to_string()))?;
    Ok(())
}

pub fn incoming_bundles(home: &Path) -> Result<Vec<PathBuf>> {
    let dir = home.join("sessions").join("incoming");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut bundles = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            bundles.push(entry.path());
        }
    }
    bundles.sort();
    Ok(bundles)
}

pub async fn send_bundle_quic(
    home: &Path,
    peer_id: &str,
    addr: &str,
    data: &[u8],
    offset: usize,
) -> Result<usize> {
    use quinn::Endpoint;

    let client_config = crate::tls::make_client_config(home, peer_id)?;
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
        .map_err(|err| AppError::new(err.to_string()))?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(addr.parse().unwrap(), "gitp2p.local")
        .map_err(|err| AppError::new(err.to_string()))?
        .await
        .map_err(|err| AppError::new(err.to_string()))?;

    let (mut send, _recv) = connection
        .open_bi()
        .await
        .map_err(|err| AppError::new(err.to_string()))?;
    let slice = &data[offset..];
    send.write_all(slice)
        .await
        .map_err(|err| AppError::new(err.to_string()))?;
    send.finish()
        .map_err(|err| AppError::new(err.to_string()))?;
    Ok(data.len())
}
