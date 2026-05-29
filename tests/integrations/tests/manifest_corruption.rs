use gitp2p_content::{new_manifest, verify_manifest, write_manifest};
use gitp2p_testing::{corrupt_manifest, temp_home};

#[test]
fn tampered_manifest_fails_validation() {
    let home = temp_home("int-manifest-corrupt");
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    let manifest = home.join("manifest.json");
    let record = new_manifest("repo-test", "cp-test", "lineage", "lineage-hash", "trusted");
    write_manifest(&manifest, &record).unwrap();

    corrupt_manifest(&manifest).unwrap();
    assert!(verify_manifest(&manifest).is_err());
}
