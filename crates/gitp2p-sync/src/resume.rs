use gitp2p_metadata::{Result, Session, SessionPhase};
use gitp2p_vault::{write_session, App};

pub fn find_resumable_session(app: &App, peer_id: &str, repo_id: &str) -> Result<Option<Session>> {
    for session in app.all_sessions()? {
        if session.peer_id == peer_id
            && session.repo_id == repo_id
            && session.phase != SessionPhase::Complete.as_str()
            && session.phase != SessionPhase::Failed.as_str()
        {
            return Ok(Some(session));
        }
    }
    Ok(None)
}

pub fn mark_session_phase(app: &App, session: &mut Session, phase: SessionPhase) -> Result<()> {
    session.phase = phase.as_str().to_string();
    write_session(app, session)
}
