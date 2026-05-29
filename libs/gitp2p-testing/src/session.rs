use gitp2p_core::{Session, SessionPhase};
use gitp2p_core::{write_session, App};

pub fn inject_incomplete_session(app: &App, peer_id: &str, repo_id: &str) -> gitp2p_core::Result<Session> {
    let session = Session {
        id: format!(
            "session-{}",
            gitp2p_core::util::stable_id(&format!("{peer_id}:{repo_id}:interrupt"))
        ),
        peer_id: peer_id.to_string(),
        repo_id: repo_id.to_string(),
        checkpoint_id: String::new(),
        direction: "push".into(),
        state: "incomplete".into(),
        encrypted: String::new(),
        created_at: gitp2p_core::util::timestamp(),
        phase: SessionPhase::Negotiating.as_str().to_string(),
        transfer_artifact: String::new(),
        bytes_transferred: "0".into(),
        transfer_offset: "0".into(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };
    write_session(app, &session)?;
    Ok(session)
}
