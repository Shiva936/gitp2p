use std::fs;
use std::path::{Path, PathBuf};

use crate::{bundle_layout, new_manifest, write_manifest, FederationManifest};
use gitp2p_core::{Result, Vault};
use gitp2p_core::util::{create_dir_all, timestamp};
use gitp2p_core::App;

pub struct VaultExport {
    pub package: PathBuf,
    pub manifest: FederationManifest,
}

pub fn export_vault(app: &App, vault_ref: &str, output: Option<PathBuf>) -> Result<VaultExport> {
    let vault = app.find_vault(vault_ref)?;
    let output = output.unwrap_or_else(|| {
        app.home
            .join("exports")
            .join(format!("{}-{}.vaultpkg", vault.name, timestamp()))
    });
    create_dir_all(&output)?;
    let layout = bundle_layout(&output);
    layout.ensure()?;

    for repo in app.all_repos()?.into_iter().filter(|r| r.vault_id == vault.id) {
        let bundle_path = layout.repository_deltas.join(format!("{}.bundle", repo.id));
        let mirror = gitp2p_core::layout::mirror_path(&vault, &repo);
        gitp2p_core::git::git(
            ["bundle", "create", bundle_path.to_string_lossy().as_ref(), "--all"],
            Some(&mirror),
        )?;
        fs::copy(
            vault.path.join("metadata").join("repos").join(&repo.id),
            layout.checkpoints.join(format!("{}.repo", repo.id)),
        )?;
    }

    let manifest = new_manifest(
        &vault.id,
        "vault-export",
        &vault.id,
        &gitp2p_core::util::stable_id(&vault.id),
        "trusted",
    );
    write_manifest(&layout.manifest, &manifest)?;
    Ok(VaultExport {
        package: output,
        manifest,
    })
}

pub fn import_vault(app: &App, package: &Path, name: Option<&str>) -> Result<Vault> {
    let layout = bundle_layout(package);
    let manifest = crate::read_manifest(&layout.manifest)?;
    crate::verify_manifest(&layout.manifest)?;
    let vault_name = name.unwrap_or(&manifest.repo_id);
    let vault = gitp2p_core::create_vault(app, vault_name)?;
    for entry in fs::read_dir(&layout.repository_deltas)? {
        let entry = entry?;
        if entry.path().extension().and_then(|s| s.to_str()) == Some("bundle") {
            crate::import_bundle(app, &entry.path(), Some(&vault.name))?;
        }
    }
    Ok(vault)
}
