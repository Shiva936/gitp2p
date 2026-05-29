use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::{bundle_layout, new_manifest, write_manifest};
use crate::{build_lineage_chain, lineage_hash};
use gitp2p_core::git::git;
use gitp2p_core::{optional_field, read_kv, Repo, RepoAction, Result, Vault};
use gitp2p_core::util::{create_dir_all, stable_id, timestamp};
use gitp2p_core::trust::enforce_repo_action;
use gitp2p_core::{
    app::write_checkpoint, app::write_repo, create_checkpoint, layout::mirror_path, latest_checkpoint,
    App,
};

pub struct ExportOptions {
    pub output: Option<PathBuf>,
    pub since_checkpoint: Option<String>,
    pub encrypt: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            output: None,
            since_checkpoint: None,
            encrypt: false,
        }
    }
}

pub struct ExportResult {
    pub bundle: PathBuf,
    pub manifest: PathBuf,
    pub encrypted: bool,
    pub incremental: bool,
}

pub fn export_bundle(app: &App, repo: &Repo, options: ExportOptions) -> Result<ExportResult> {
    let vault = app.find_vault(&repo.vault_id)?;
    enforce_repo_action(repo, RepoAction::Export, false, false)?;
    let checkpoint = latest_checkpoint(app, &repo.id)
        .or_else(|_| create_checkpoint(app, Some(&repo.id), false, false, false))?;
    let output = options.output.unwrap_or_else(|| {
        vault
            .path
            .join("bundles")
            .join(format!("{}-{}.bundle", repo.name, checkpoint.id))
    });
    if let Some(parent) = output.parent() {
        create_dir_all(parent)?;
    }
    let mirror = mirror_path(&vault, repo);
    let incremental = if let Some(since_id) = &options.since_checkpoint {
        let (_, _, since_cp) = app.find_checkpoint(since_id)?;
        git(
            [
                "bundle",
                "create",
                output.to_string_lossy().as_ref(),
                &since_cp.commit,
                "HEAD",
            ],
            Some(&mirror),
        )?;
        true
    } else {
        git(
            [
                "bundle",
                "create",
                output.to_string_lossy().as_ref(),
                "--all",
            ],
            Some(&mirror),
        )?;
        false
    };

    let bundle_path = if options.encrypt {
        let encrypted = encrypt_file(&output)?;
        fs::remove_file(&output).ok();
        encrypted
    } else {
        output
    };

    let manifest = bundle_path.with_extension("bundle.meta");
    gitp2p_core::write_kv(
        &manifest,
        &[
            ("repo_id", &repo.id),
            ("repo_name", &repo.name),
            ("vault_id", &vault.id),
            ("checkpoint_id", &checkpoint.id),
            ("commit", &checkpoint.commit),
            ("created_at", &timestamp()),
            ("trust_zone", &repo.trust_zone),
            ("encrypted", if options.encrypt { "true" } else { "false" }),
            ("incremental", if incremental { "true" } else { "false" }),
        ],
    )?;
    Ok(ExportResult {
        bundle: bundle_path,
        manifest,
        encrypted: options.encrypt,
        incremental,
    })
}

pub fn export_bundle_simple(app: &App, repo: &Repo, output: Option<PathBuf>) -> Result<ExportResult> {
    export_bundle(
        app,
        repo,
        ExportOptions {
            output,
            ..Default::default()
        },
    )
}

fn encrypt_file(path: &Path) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let key_material = env::var("GITP2P_BUNDLE_KEY").unwrap_or_else(|_| "gitp2p-default-key".into());
    let key = Sha256::digest(key_material.as_bytes());
    let data = fs::read(path)?;
    let mut out = Vec::with_capacity(data.len());
    for (i, byte) in data.iter().enumerate() {
        out.push(byte ^ key[i % key.len()]);
    }
    let enc_path = path.with_extension("bundle.enc");
    fs::write(&enc_path, out)?;
    Ok(enc_path)
}

fn decrypt_file(path: &Path) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let key_material = env::var("GITP2P_BUNDLE_KEY").unwrap_or_else(|_| "gitp2p-default-key".into());
    let key = Sha256::digest(key_material.as_bytes());
    let data = fs::read(path)?;
    let mut out = Vec::with_capacity(data.len());
    for (i, byte) in data.iter().enumerate() {
        out.push(byte ^ key[i % key.len()]);
    }
    let dec_path = path.with_extension("bundle.dec");
    fs::write(&dec_path, out)?;
    Ok(dec_path)
}

pub fn validate_bundle(bundle: &Path) -> Result<()> {
    let path = if bundle.extension().and_then(|s| s.to_str()) == Some("enc") {
        decrypt_file(bundle)?
    } else {
        bundle.to_path_buf()
    };
    git(["bundle", "verify", path.to_string_lossy().as_ref()], None)?;
    Ok(())
}

pub fn import_bundle(app: &App, bundle: &Path, vault_ref: Option<&str>) -> Result<(Vault, Repo)> {
    if !bundle.exists() {
        return Err(gitp2p_core::AppError::new(format!(
            "bundle '{}' does not exist",
            bundle.display()
        )));
    }
    let bundle_path = if bundle.extension().and_then(|s| s.to_str()) == Some("enc") {
        decrypt_file(bundle)?
    } else {
        bundle.to_path_buf()
    };
    git(["bundle", "verify", bundle_path.to_string_lossy().as_ref()], None)?;
    let vault = match vault_ref {
        Some(reference) => app.find_vault(reference)?,
        None => app
            .all_vaults()?
            .into_iter()
            .next()
            .ok_or_else(|| gitp2p_core::AppError::new("no vault exists; create one or pass --vault"))?,
    };

    let manifest_path = bundle.with_extension("bundle.meta");
    let (repo_id, repo_name, trust_zone, checkpoint_id, commit) = if manifest_path.exists() {
        let map = read_kv(&manifest_path)?;
        (
            optional_field(&map, "repo_id"),
            optional_field(&map, "repo_name"),
            optional_field(&map, "trust_zone"),
            optional_field(&map, "checkpoint_id"),
            optional_field(&map, "commit"),
        )
    } else {
        (
            String::new(),
            String::new(),
            "trusted".into(),
            String::new(),
            String::new(),
        )
    };

    let stem = bundle
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("imported");
    let repo_id = if repo_id.is_empty() {
        format!("repo-import-{}", stable_id(&format!("{stem}:{}", timestamp())))
    } else {
        repo_id
    };
    let repo_name = if repo_name.is_empty() {
        stem.to_string()
    } else {
        repo_name
    };
    let mirror = vault
        .path
        .join("repositories")
        .join(format!("{repo_id}.git"));
    git(
        [
            "clone",
            "--mirror",
            bundle_path.to_string_lossy().as_ref(),
            mirror.to_string_lossy().as_ref(),
        ],
        None,
    )?;

    let repo = Repo {
        id: repo_id.clone(),
        name: repo_name.clone(),
        path: PathBuf::from(format!("imported://{repo_name}")),
        vault_id: vault.id.clone(),
        trust_zone: if trust_zone.is_empty() {
            "trusted".into()
        } else {
            trust_zone
        },
        sync_state: "imported".into(),
        latest_checkpoint: checkpoint_id.clone(),
        created_at: timestamp(),
    };
    write_repo(&vault, &repo)?;

    if !checkpoint_id.is_empty() && !commit.is_empty() {
        let mut checkpoint = gitp2p_core::Checkpoint {
            id: checkpoint_id,
            repo_id: repo.id.clone(),
            vault_id: vault.id.clone(),
            commit,
            parent: String::new(),
            created_at: timestamp(),
            status: "imported-verified".into(),
            signature: String::new(),
            signed_by: String::new(),
            signed_at: String::new(),
        };
        if let Ok(identity) = app.ensure_identity() {
            gitp2p_core::trust::sign_checkpoint(&identity, &mut checkpoint)?;
        }
        let cp_path = vault
            .path
            .join("metadata")
            .join("checkpoints")
            .join(&checkpoint.id);
        if !cp_path.exists() {
            write_checkpoint(&vault, &checkpoint)?;
        }
    }

    Ok((vault, repo))
}

pub fn create_structured_bundle(
    app: &App,
    repo: &Repo,
    output: Option<PathBuf>,
    encrypt: bool,
) -> Result<ExportResult> {
    let vault = app.find_vault(&repo.vault_id)?;
    enforce_repo_action(repo, RepoAction::Export, false, false)?;
    let checkpoint = latest_checkpoint(app, &repo.id)
        .or_else(|_| create_checkpoint(app, Some(&repo.id), false, false, false))?;
    let root = output.unwrap_or_else(|| {
        vault
            .path
            .join("bundles")
            .join(format!("{}-{}-pkg", repo.name, checkpoint.id))
    });
    let layout = bundle_layout(&root);
    layout.ensure()?;

    let mirror = mirror_path(&vault, repo);
    let bundle_file = layout.repository_deltas.join(format!("{}.bundle", repo.id));
    git(
        ["bundle", "create", bundle_file.to_string_lossy().as_ref(), "--all"],
        Some(&mirror),
    )?;

    let chain = build_lineage_chain(app, &checkpoint)?;
    let lhash = lineage_hash(&chain);
    std::fs::write(&layout.lineage.join("chain.txt"), &chain)?;
    gitp2p_core::write_kv(
        &layout.checkpoints.join(format!("{}.cp", checkpoint.id)),
        &[
            ("id", &checkpoint.id),
            ("commit", &checkpoint.commit),
            ("repo_id", &repo.id),
        ],
    )?;
    gitp2p_core::write_kv(
        &layout.trust.join("zone"),
        &[("trust_zone", &repo.trust_zone)],
    )?;

    let manifest = new_manifest(
        &repo.id,
        &checkpoint.id,
        &chain,
        &lhash,
        &repo.trust_zone,
    );
    write_manifest(&layout.manifest, &manifest)?;

    if encrypt {
        let _enc = encrypt_file(&bundle_file)?;
    }
    Ok(ExportResult {
        bundle: root,
        manifest: layout.manifest,
        encrypted: encrypt,
        incremental: false,
    })
}
