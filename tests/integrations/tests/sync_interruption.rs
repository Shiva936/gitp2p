use gitp2p_sync::resume::find_resumable_session;
use gitp2p_testing::{inject_incomplete_session, setup_vault_with_repo};

#[test]
fn incomplete_session_is_resumable() {
    let app = setup_vault_with_repo("int-sync-interrupt");
    let repo = app.all_repos().unwrap().pop().unwrap();
    let session = inject_incomplete_session(&app, "peer-interrupt", &repo.id).unwrap();

    let found = find_resumable_session(&app, "peer-interrupt", &repo.id)
        .unwrap()
        .expect("resumable session");
    assert_eq!(found.id, session.id);
    assert_ne!(found.phase, "complete");
}
