use gitp2p_metadata::{Checkpoint, Identity, Result, Session};
use gitp2p_metadata::util::timestamp;

use crate::identity::{sign_bytes, verify_bytes};

pub fn checkpoint_payload(checkpoint: &Checkpoint) -> String {
    format!(
        "checkpoint:{}:{}:{}:{}:{}",
        checkpoint.id,
        checkpoint.repo_id,
        checkpoint.vault_id,
        checkpoint.commit,
        checkpoint.parent
    )
}

pub fn session_payload(session: &Session) -> String {
    format!(
        "session:{}:{}:{}:{}:{}:{}",
        session.id,
        session.peer_id,
        session.repo_id,
        session.checkpoint_id,
        session.direction,
        session.phase
    )
}

pub fn replication_payload(
    peer_id: &str,
    repo_id: &str,
    checkpoint_id: &str,
    propagation_state: &str,
) -> String {
    format!("replication:{peer_id}:{repo_id}:{checkpoint_id}:{propagation_state}")
}

pub fn sign_checkpoint(identity: &Identity, checkpoint: &mut Checkpoint) -> Result<()> {
    let payload = checkpoint_payload(checkpoint);
    checkpoint.signature = sign_bytes(identity, payload.as_bytes())?;
    checkpoint.signed_by = identity.peer_id.clone();
    checkpoint.signed_at = timestamp();
    Ok(())
}

pub fn verify_checkpoint(checkpoint: &Checkpoint, public_key: &str) -> Result<()> {
    if checkpoint.signature.is_empty() {
        return Ok(());
    }
    let payload = checkpoint_payload(checkpoint);
    verify_bytes(public_key, payload.as_bytes(), &checkpoint.signature)
}

pub fn sign_session(identity: &Identity, session: &mut Session) -> Result<()> {
    let payload = session_payload(session);
    session.signature = sign_bytes(identity, payload.as_bytes())?;
    session.signed_by = identity.peer_id.clone();
    session.signed_at = timestamp();
    session.encrypted = session.signature.clone();
    Ok(())
}

pub fn verify_session(session: &Session, public_key: &str) -> Result<()> {
    if session.signature.is_empty() {
        return Ok(());
    }
    let payload = session_payload(session);
    verify_bytes(public_key, payload.as_bytes(), &session.signature)
}

pub fn sign_replication(
    identity: &Identity,
    peer_id: &str,
    repo_id: &str,
    checkpoint_id: &str,
    propagation_state: &str,
) -> Result<(String, String, String)> {
    let payload = replication_payload(peer_id, repo_id, checkpoint_id, propagation_state);
    let signature = sign_bytes(identity, payload.as_bytes())?;
    Ok((signature, identity.peer_id.clone(), timestamp()))
}

pub fn verify_replication(
    public_key: &str,
    peer_id: &str,
    repo_id: &str,
    checkpoint_id: &str,
    propagation_state: &str,
    signature: &str,
) -> Result<()> {
    if signature.is_empty() {
        return Ok(());
    }
    let payload = replication_payload(peer_id, repo_id, checkpoint_id, propagation_state);
    verify_bytes(public_key, payload.as_bytes(), signature)
}
