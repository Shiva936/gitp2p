use gitp2p_content::{cas_root, verify_chunk};
use gitp2p_testing::{corrupt_cas_chunk, seed_cas_chunk, setup_vault_with_repo};

#[test]
fn corrupt_cas_chunk_detected_and_restored() {
    let app = setup_vault_with_repo("int-cas-corrupt");
    let data = b"benchmark chunk payload";
    let chunk_id = seed_cas_chunk(&app, data).unwrap();

    corrupt_cas_chunk(&app, &chunk_id).unwrap();
    assert!(verify_chunk(&cas_root(&app.home), &chunk_id).is_err());

    let prefix = &chunk_id[6..8.min(chunk_id.len())];
    std::fs::remove_file(cas_root(&app.home).join(prefix).join(&chunk_id)).unwrap();
    let restored = seed_cas_chunk(&app, data).unwrap();
    assert_eq!(restored, chunk_id);
    verify_chunk(&cas_root(&app.home), &chunk_id).unwrap();
}
