use gitp2p_core::create_checkpoint;
use gitp2p_sync::recovery::{doctor_repo, recover_local};
use gitp2p_testing::{setup_vault_with_repo, truncate_repo_ref};

#[test]
fn corrupt_repo_then_recover_from_mirror() {
    let app = setup_vault_with_repo("int-corrupt-recover");
    let repo = app.all_repos().unwrap().pop().unwrap();
    create_checkpoint(&app, Some(&repo.id), false, false, false).unwrap();

    truncate_repo_ref(&repo.path).unwrap();
    let report = doctor_repo(&repo).unwrap();
    assert!(!report.healthy);

    recover_local(&app, &repo, None, None, true).unwrap();
    let after = doctor_repo(&repo).unwrap();
    assert!(after.healthy);
}
