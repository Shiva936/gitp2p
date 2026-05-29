use gitp2p_core::{Checkpoint, Peer, Repo, Result, Session};
use gitp2p_core::App;

pub trait Transport {
    fn name(&self) -> &'static str;

    fn replicate(
        &self,
        app: &App,
        repo: &Repo,
        checkpoint: &Checkpoint,
        peer: &Peer,
        requires_approval: bool,
        session: &mut Session,
    ) -> Result<()>;
}

pub struct FilesystemTransport;

impl Transport for FilesystemTransport {
    fn name(&self) -> &'static str {
        "filesystem"
    }

    fn replicate(
        &self,
        app: &App,
        repo: &Repo,
        checkpoint: &Checkpoint,
        peer: &Peer,
        requires_approval: bool,
        session: &mut Session,
    ) -> Result<()> {
        crate::replication::replicate_filesystem(
            app,
            repo,
            checkpoint,
            peer,
            requires_approval,
            session,
        )
    }
}

pub fn select_transport(mode: &str, peer: &Peer) -> Box<dyn Transport> {
    match mode {
        "quic" => Box::new(QuicTransport),
        "filesystem" => Box::new(FilesystemTransport),
        "auto" => {
            if peer.home.as_os_str().is_empty() {
                Box::new(QuicTransport)
            } else if peer.listen_port > 0 {
                Box::new(AutoTransport)
            } else {
                Box::new(FilesystemTransport)
            }
        }
        _ => Box::new(FilesystemTransport),
    }
}

pub struct AutoTransport;

impl Transport for AutoTransport {
    fn name(&self) -> &'static str {
        "auto"
    }

    fn replicate(
        &self,
        app: &App,
        repo: &Repo,
        checkpoint: &Checkpoint,
        peer: &Peer,
        requires_approval: bool,
        session: &mut Session,
    ) -> Result<()> {
        if peer.home.exists() && peer.home.join("identity").exists() {
            return FilesystemTransport.replicate(
                app,
                repo,
                checkpoint,
                peer,
                requires_approval,
                session,
            );
        }
        QuicTransport.replicate(
            app,
            repo,
            checkpoint,
            peer,
            requires_approval,
            session,
        )
    }
}

pub struct QuicTransport;

impl Transport for QuicTransport {
    fn name(&self) -> &'static str {
        "quic"
    }

    fn replicate(
        &self,
        app: &App,
        repo: &Repo,
        checkpoint: &Checkpoint,
        peer: &Peer,
        requires_approval: bool,
        session: &mut Session,
    ) -> Result<()> {
        if peer.home.exists() && peer.home.join("identity").exists() {
            return FilesystemTransport.replicate(
                app,
                repo,
                checkpoint,
                peer,
                requires_approval,
                session,
            );
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|err| gitp2p_core::AppError::new(err.to_string()))?;
        runtime.block_on(async {
            quic_replicate(app, repo, checkpoint, peer, requires_approval, session).await
        })
    }
}

async fn quic_replicate(
    app: &App,
    repo: &Repo,
    checkpoint: &Checkpoint,
    peer: &Peer,
    requires_approval: bool,
    session: &mut Session,
) -> Result<()> {
    use gitp2p_core::git::git;
    use gitp2p_core::util::create_dir_all;

    let bundle_dir = app.home.join("sessions").join("artifacts");
    create_dir_all(&bundle_dir)?;
    let bundle_path = bundle_dir.join(format!("{}-{}.bundle", repo.id, checkpoint.id));
    session.transfer_artifact = bundle_path.to_string_lossy().to_string();

    let vault = app.find_vault(&repo.vault_id)?;
    let mirror = gitp2p_core::layout::mirror_path(&vault, repo);
    let remote_mirror = if peer.home.exists() {
        gitp2p_core::ensure_remote_vault(
            &gitp2p_core::App::with_home(peer.home.clone()),
            &vault,
        )
        .ok()
        .map(|remote_vault| gitp2p_core::layout::mirror_path(&remote_vault, repo))
    } else {
        None
    };
    let negotiation = crate::negotiate::negotiate_refs(app, repo, remote_mirror.as_deref())?;
    if negotiation.incremental {
        git(
            [
                "bundle",
                "create",
                bundle_path.to_string_lossy().as_ref(),
                &negotiation.local_head,
            ],
            Some(&mirror),
        )?;
    } else {
        git(
            [
                "bundle",
                "create",
                bundle_path.to_string_lossy().as_ref(),
                "--all",
            ],
            Some(&mirror),
        )?;
    }

    let data = tokio::fs::read(&bundle_path).await?;
    let offset = session
        .transfer_offset
        .parse::<usize>()
        .unwrap_or(0)
        .min(data.len());
    let addr = format!("127.0.0.1:{}", peer.listen_port);

    let sent = crate::quic_server::send_bundle_quic(&app.home, &peer.id, &addr, &data, offset).await;
    if sent.is_err() && peer.home.exists() {
        return FilesystemTransport.replicate(
            app,
            repo,
            checkpoint,
            peer,
            requires_approval,
            session,
        );
    }
    let total = sent?;
    session.bytes_transferred = total.to_string();
    session.transfer_offset = total.to_string();
    session.encrypted = "tls-pinned".to_string();
    gitp2p_core::write_session(app, session)?;

    if peer.home.exists() {
        return crate::replication::replicate_filesystem(
            app,
            repo,
            checkpoint,
            peer,
            requires_approval,
            session,
        );
    }
    Ok(())
}
