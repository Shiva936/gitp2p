use std::env;
use std::path::PathBuf;

use gitp2p_metadata::{Checkpoint, Identity, Peer, Repo, Result, Session, SessionPhase};
use gitp2p_metadata::git::git;
use gitp2p_metadata::util::{append_replication_log, listen_port, timestamp, transport_mode};
use gitp2p_trust::{
    authorize_peer, enforce_peer_policy, merged_policy, peer_is_trusted, sign_replication,
    sign_session, verify_checkpoint, verify_replication, verify_session, write_peer,
};
use gitp2p_trust::validate_peer_identity;
use gitp2p_vault::{
    checkpoint_lineage, copy_checkpoint_if_missing, create_checkpoint, ensure_remote_vault,
    layout::mirror_path, validate_checkpoint_for_sync, write_session, App,
};

use crate::resume::{find_resumable_session, mark_session_phase};
use crate::transport::{select_transport, Transport};

pub fn sync_local(
    app: &App,
    repo_ref: Option<&str>,
    enforce_retention: bool,
) -> Result<Checkpoint> {
    create_checkpoint(app, repo_ref, enforce_retention, false, false)
}

pub fn sync_to_peer(
    app: &App,
    repo_ref: Option<&str>,
    peer_id: &str,
    requires_approval: bool,
    enforce_retention: bool,
) -> Result<Session> {
    let _slot = crate::concurrent::SyncSlot::acquire(&app.home)?;
    let peer = app.find_peer(peer_id)?;
    validate_peer_identity(&peer.public_key)?;
    authorize_peer(&peer, requires_approval)?;
    let repo = app.find_repo(repo_ref)?;
    let vault = app.find_vault(&repo.vault_id)?;
    let policy = merged_policy(&vault, Some(&repo.id))?;
    enforce_peer_policy(&policy, &peer.id)?;
    let peer_trusted = peer_is_trusted(&peer);
    validate_checkpoint_for_sync(&repo, requires_approval, peer_trusted)?;

    if let Some(mut existing) = find_resumable_session(app, &peer.id, &repo.id)? {
        let transport = select_transport(&transport_mode(), &peer);
        return resume_session(app, &repo, &peer, &mut existing, requires_approval, transport.as_ref());
    }

    let checkpoint = create_checkpoint(
        app,
        repo_ref,
        enforce_retention,
        requires_approval,
        peer_trusted,
    )?;
    verify_checkpoint(&checkpoint, &app.ensure_identity()?.public_key)?;

    let mut session = new_session(&peer, &repo, &checkpoint, requires_approval);
    mark_session_phase(app, &mut session, SessionPhase::Authenticated)?;
    let transport = select_transport(&transport_mode(), &peer);
    mark_session_phase(app, &mut session, SessionPhase::Negotiating)?;
    let _negotiation = crate::negotiate::negotiate_refs(app, &repo, None)?;
    transport.replicate(
        app,
        &repo,
        &checkpoint,
        &peer,
        requires_approval,
        &mut session,
    )?;
    mark_session_phase(app, &mut session, SessionPhase::Complete)?;
    Ok(session)
}

fn new_session(peer: &Peer, repo: &Repo, checkpoint: &Checkpoint, requires_approval: bool) -> Session {
    Session {
        id: format!(
            "session-{}",
            gitp2p_metadata::util::stable_id(&format!("{}:{}:{}", peer.id, repo.id, timestamp()))
        ),
        peer_id: peer.id.clone(),
        repo_id: repo.id.clone(),
        checkpoint_id: checkpoint.id.clone(),
        direction: "push".to_string(),
        state: if requires_approval {
            "approved-replicated".to_string()
        } else {
            "replicated".to_string()
        },
        encrypted: String::new(),
        created_at: timestamp(),
        phase: SessionPhase::Discovered.as_str().to_string(),
        transfer_artifact: String::new(),
        bytes_transferred: "0".to_string(),
        transfer_offset: "0".to_string(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    }
}

fn resume_session(
    app: &App,
    repo: &Repo,
    peer: &Peer,
    session: &mut Session,
    requires_approval: bool,
    transport: &dyn Transport,
) -> Result<Session> {
    let checkpoint = app.find_checkpoint(&session.checkpoint_id)?.2;
    verify_session(session, &peer.public_key)?;
    mark_session_phase(app, session, SessionPhase::Transferring)?;
    transport.replicate(app, repo, &checkpoint, peer, requires_approval, session)?;
    mark_session_phase(app, session, SessionPhase::Complete)?;
    Ok(session.clone())
}

pub fn replicate_filesystem(
    app: &App,
    repo: &Repo,
    checkpoint: &Checkpoint,
    peer: &Peer,
    requires_approval: bool,
    session: &mut Session,
) -> Result<()> {
    let local_vault = app.find_vault(&repo.vault_id)?;
    let remote_app = App::with_home(peer.home.clone());
    remote_app.ensure_home()?;
    remote_app.ensure_identity()?;
    let remote_vault = ensure_remote_vault(&remote_app, &local_vault)?;
    let local_mirror = mirror_path(&local_vault, repo);
    let remote_mirror = mirror_path(&remote_vault, repo);

    mark_session_phase(app, session, SessionPhase::Transferring)?;
    session.transfer_artifact = remote_mirror.to_string_lossy().to_string();

    if remote_mirror.exists() {
        git(
            [
                "remote",
                "set-url",
                "origin",
                local_mirror.to_string_lossy().as_ref(),
            ],
            Some(&remote_mirror),
        )?;
        git(["remote", "update", "--prune"], Some(&remote_mirror))?;
    } else {
        git(
            [
                "clone",
                "--mirror",
                local_mirror.to_string_lossy().as_ref(),
                remote_mirror.to_string_lossy().as_ref(),
            ],
            None,
        )?;
    }

    let local_identity = app.ensure_identity()?;
    let mut remote_repo = repo.clone();
    remote_repo.path = PathBuf::from(format!(
        "peer-replica://{}/{}",
        local_identity.peer_id, repo.name
    ));
    remote_repo.sync_state = "replicated".to_string();
    gitp2p_vault::app::write_repo(&remote_vault, &remote_repo)?;
    copy_checkpoint_if_missing(&remote_vault, checkpoint)?;

    mark_session_phase(app, session, SessionPhase::Propagating)?;
    let identity = app.ensure_identity()?;
    sign_session(&identity, session)?;
    write_session(app, session)?;
    write_session(&remote_app, session)?;

    let lineage = checkpoint_lineage(app, checkpoint)?;
    let propagation_state = "complete";
    let (signature, signed_by, signed_at) = sign_replication(
        &identity,
        &peer.id,
        &repo.id,
        &checkpoint.id,
        propagation_state,
    )?;
    verify_replication(
        &identity.public_key,
        &peer.id,
        &repo.id,
        &checkpoint.id,
        propagation_state,
        &signature,
    )?;

    write_replication_state(
        &local_vault,
        peer,
        repo,
        checkpoint,
        session,
        &lineage,
        propagation_state,
        &signature,
        &signed_by,
        &signed_at,
    )?;
    write_replication_state(
        &remote_vault,
        peer,
        repo,
        checkpoint,
        session,
        &lineage,
        propagation_state,
        &signature,
        &signed_by,
        &signed_at,
    )?;
    append_replication_log(
        &local_vault,
        &peer.id,
        &repo.id,
        &format!("replicated checkpoint={} session={}", checkpoint.id, session.id),
    )?;

    mark_session_phase(app, session, SessionPhase::Validating)?;
    git(["fsck", "--full"], Some(&remote_mirror))?;
    session.bytes_transferred = session
        .bytes_transferred
        .parse::<usize>()
        .map(|n| n.to_string())
        .unwrap_or_else(|_| "complete".to_string());
    if session.transfer_offset.is_empty() {
        session.transfer_offset = session.bytes_transferred.clone();
    }
    write_session(app, session)?;
    write_session(&remote_app, session)?;
    Ok(())
}

pub fn replication_history(app: &App, peer_id: Option<&str>) -> Result<Vec<(String, String, String)>> {
    let mut history = Vec::new();
    for vault in app.all_vaults()? {
        let dir = vault.path.join("replication");
        if !dir.exists() {
            continue;
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let map = gitp2p_metadata::read_kv(&entry.path())?;
                let pid = gitp2p_metadata::optional_field(&map, "peer_id");
                if peer_id.map(|id| id == pid).unwrap_or(true) {
                    history.push((
                        pid,
                        gitp2p_metadata::optional_field(&map, "repo_id"),
                        gitp2p_metadata::optional_field(&map, "sync_history"),
                    ));
                }
            }
        }
    }
    Ok(history)
}

pub fn write_replication_state(
    vault: &gitp2p_metadata::Vault,
    peer: &Peer,
    repo: &Repo,
    checkpoint: &Checkpoint,
    session: &Session,
    lineage: &str,
    propagation_state: &str,
    signature: &str,
    signed_by: &str,
    signed_at: &str,
) -> Result<()> {
    gitp2p_metadata::write_kv_atomic(
        &vault
            .path
            .join("replication")
            .join(format!("{}-{}", peer.id, repo.id)),
        &[
            ("peer_id", &peer.id),
            ("repo_id", &repo.id),
            ("checkpoint_id", &checkpoint.id),
            ("session_id", &session.id),
            ("state", &session.state),
            ("updated_at", &timestamp()),
            ("checkpoint_lineage", lineage),
            ("propagation_state", propagation_state),
            ("sync_history", &session.id),
            ("signature", signature),
            ("signed_by", signed_by),
            ("signed_at", signed_at),
        ],
    )
}

pub fn discover_filesystem(app: &App, homes: &[PathBuf]) -> Result<Vec<Peer>> {
    let mut discovered = Vec::new();
    let identity = app.ensure_identity()?;
    for home in homes {
        let identity_path = home.join("identity");
        if !identity_path.exists() || home == &app.home {
            continue;
        }
        let remote_identity = gitp2p_trust::load_identity(&identity_path)?;
        validate_peer_identity(&remote_identity.public_key)?;
        let remote_app = App::with_home(home.clone());
        let vaults = remote_app
            .all_vaults()
            .unwrap_or_default()
            .into_iter()
            .map(|vault| vault.name)
            .collect::<Vec<_>>()
            .join(",");
        let trust_state = app
            .all_peers()?
            .into_iter()
            .find(|peer| peer.id == remote_identity.peer_id)
            .map(|peer| peer.trust_state)
            .unwrap_or_else(|| "untrusted".to_string());
        let peer = Peer {
            id: remote_identity.peer_id,
            public_key: remote_identity.public_key,
            home: home.clone(),
            trust_state,
            capabilities: "filesystem,encrypted-session,checkpoint-replication,quic".to_string(),
            vaults,
            discovered_at: timestamp(),
            listen_port: listen_port(),
        };
        write_peer(&app.home, &peer)?;
        discovered.push(peer);
    }
    let _ = identity;
    Ok(discovered)
}

pub fn list_inflight_sessions(app: &App, repo_id: Option<&str>) -> Result<Vec<Session>> {
    Ok(app
        .all_sessions()?
        .into_iter()
        .filter(|session| {
            session.phase != SessionPhase::Complete.as_str()
                && session.phase != SessionPhase::Failed.as_str()
                && repo_id.map(|id| id == session.repo_id).unwrap_or(true)
        })
        .collect())
}
