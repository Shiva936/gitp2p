use gitp2p_content::{cas_root, chunk_id, store_chunk, verify_chunk};
use gitp2p_content::deduplicate_store;
use gitp2p_core::identity::{peer_id_from_key, vault_id};
use gitp2p_content::merkle_root;
use gitp2p_core::App;

#[test]
fn cas_dedup_and_merkle() {
    let home = std::env::temp_dir().join(format!(
        "gitp2p-v45-{}",
        gitp2p_core::util::stable_id("cas")
    ));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let app = App::with_home(home.clone());
    app.ensure_home().unwrap();

    let data = b"hello federation chunk";
    let id = store_chunk(&cas_root(&app.home), data).unwrap();
    assert_eq!(id, chunk_id(data));
    verify_chunk(&cas_root(&app.home), &id).unwrap();

    let (id2, is_new) = deduplicate_store(&app.home, data).unwrap();
    assert_eq!(id, id2);
    assert!(!is_new);

    let root = merkle_root(&["a", "b", "c"]);
    assert_eq!(root, merkle_root(&["a", "b", "c"]));

    assert!(vault_id("test").starts_with("vault-"));
    assert!(peer_id_from_key("test-key").starts_with("peer-"));
}
