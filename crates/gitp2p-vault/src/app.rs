use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use gitp2p_metadata::{
    field, optional_field, read_kv, write_kv, AppError, Checkpoint, Identity, Peer, Repo,
    Result, Vault,
};
use gitp2p_metadata::util::{create_dir_all, default_home};
use gitp2p_trust::ensure_identity;

#[derive(Clone, Debug)]
pub struct App {
    pub home: PathBuf,
}

impl App {
    pub fn load() -> Result<Self> {
        Ok(Self {
            home: default_home()?,
        })
    }

    pub fn with_home(home: PathBuf) -> Self {
        Self { home }
    }

    pub fn ensure_home(&self) -> Result<()> {
        create_dir_all(self.home.join("vaults"))?;
        create_dir_all(self.home.join("peers"))?;
        create_dir_all(self.home.join("sessions"))?;
        Ok(())
    }

    pub fn ensure_identity(&self) -> Result<Identity> {
        ensure_identity(&self.home.join("identity"))
    }

    pub fn vaults_dir(&self) -> PathBuf {
        self.home.join("vaults")
    }

    pub fn all_vaults(&self) -> Result<Vec<Vault>> {
        let mut vaults = Vec::new();
        if !self.vaults_dir().exists() {
            return Ok(vaults);
        }
        for entry in fs::read_dir(self.vaults_dir())? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let meta_path = entry.path().join("metadata").join("vault");
                if meta_path.exists() {
                    vaults.push(read_vault(&entry.path())?);
                }
            }
        }
        vaults.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(vaults)
    }

    pub fn find_vault(&self, reference: &str) -> Result<Vault> {
        self.all_vaults()?
            .into_iter()
            .find(|vault| vault.id == reference || vault.name == reference)
            .ok_or_else(|| AppError::new(format!("vault '{reference}' was not found")))
    }

    pub fn all_repos(&self) -> Result<Vec<Repo>> {
        let mut repos = Vec::new();
        for vault in self.all_vaults()? {
            let repo_dir = vault.path.join("metadata").join("repos");
            if !repo_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(repo_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    repos.push(read_repo(&entry.path())?);
                }
            }
        }
        repos.sort_by(|a, b| a.name.cmp(&b.name).then(a.path.cmp(&b.path)));
        Ok(repos)
    }

    pub fn find_repo(&self, reference: Option<&str>) -> Result<Repo> {
        let repos = self.all_repos()?;
        if let Some(reference) = reference {
            return repos
                .into_iter()
                .find(|repo| {
                    repo.id == reference
                        || repo.name == reference
                        || repo.path == PathBuf::from(reference)
                })
                .ok_or_else(|| {
                    AppError::new(format!("repository '{reference}' was not registered"))
                });
        }

        let cwd = env::current_dir()?.canonicalize()?;
        repos
            .into_iter()
            .find(|repo| repo.path == cwd)
            .ok_or_else(|| {
                AppError::new(
                    "current directory is not a registered repository; pass a repository name or id",
                )
            })
    }

    pub fn find_checkpoint(&self, reference: &str) -> Result<(Vault, Repo, Checkpoint)> {
        for vault in self.all_vaults()? {
            let cp_dir = vault.path.join("metadata").join("checkpoints");
            if !cp_dir.exists() {
                continue;
            }
            for entry in fs::read_dir(cp_dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    let checkpoint = read_checkpoint(&entry.path())?;
                    if checkpoint.id == reference {
                        let repo = self.find_repo(Some(&checkpoint.repo_id))?;
                        return Ok((vault, repo, checkpoint));
                    }
                }
            }
        }
        Err(AppError::new(format!(
            "checkpoint '{reference}' was not found"
        )))
    }

    pub fn all_peers(&self) -> Result<Vec<Peer>> {
        let mut peers = Vec::new();
        let dir = self.home.join("peers");
        if !dir.exists() {
            return Ok(peers);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                peers.push(gitp2p_trust::read_peer(&entry.path())?);
            }
        }
        peers.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(peers)
    }

    pub fn find_peer(&self, reference: &str) -> Result<Peer> {
        self.all_peers()?
            .into_iter()
            .find(|peer| peer.id == reference)
            .ok_or_else(|| {
                AppError::new(format!(
                    "peer '{reference}' is not known; run peers discover first"
                ))
            })
    }

    pub fn all_sessions(&self) -> Result<Vec<gitp2p_metadata::Session>> {
        let mut sessions = Vec::new();
        let dir = self.home.join("sessions");
        if !dir.exists() {
            return Ok(sessions);
        }
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                sessions.push(read_session(&entry.path())?);
            }
        }
        sessions.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        Ok(sessions)
    }

    pub fn find_session(&self, id: &str) -> Result<gitp2p_metadata::Session> {
        let path = self.home.join("sessions").join(id);
        if path.exists() {
            return read_session(&path);
        }
        Err(AppError::new(format!("session '{id}' was not found")))
    }
}

pub fn read_vault(path: &Path) -> Result<Vault> {
    let map = read_kv(&path.join("metadata").join("vault"))?;
    Ok(Vault {
        id: field(&map, "id")?,
        name: field(&map, "name")?,
        path: path.to_path_buf(),
        created_at: field(&map, "created_at")?,
    })
}

pub fn read_repo(path: &Path) -> Result<Repo> {
    let map = read_kv(path)?;
    Ok(Repo {
        id: field(&map, "id")?,
        name: field(&map, "name")?,
        path: PathBuf::from(field(&map, "path")?),
        vault_id: field(&map, "vault_id")?,
        trust_zone: field(&map, "trust_zone")?,
        sync_state: field(&map, "sync_state")?,
        latest_checkpoint: optional_field(&map, "latest_checkpoint"),
        created_at: field(&map, "created_at")?,
    })
}

pub fn write_repo(vault: &Vault, repo: &Repo) -> Result<()> {
    write_kv(
        &vault.path.join("metadata").join("repos").join(&repo.id),
        &[
            ("id", &repo.id),
            ("name", &repo.name),
            ("path", &repo.path.to_string_lossy()),
            ("vault_id", &repo.vault_id),
            ("trust_zone", &repo.trust_zone),
            ("sync_state", &repo.sync_state),
            ("latest_checkpoint", &repo.latest_checkpoint),
            ("created_at", &repo.created_at),
        ],
    )
}

pub fn read_checkpoint(path: &Path) -> Result<Checkpoint> {
    let map = read_kv(path)?;
    Ok(Checkpoint {
        id: field(&map, "id")?,
        repo_id: field(&map, "repo_id")?,
        vault_id: field(&map, "vault_id")?,
        commit: field(&map, "commit")?,
        parent: optional_field(&map, "parent"),
        created_at: field(&map, "created_at")?,
        status: field(&map, "status")?,
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_checkpoint(vault: &Vault, checkpoint: &Checkpoint) -> Result<()> {
    let path = vault
        .path
        .join("metadata")
        .join("checkpoints")
        .join(&checkpoint.id);
    if path.exists() {
        return Err(AppError::new(
            "checkpoint id collision; refusing to overwrite immutable metadata",
        ));
    }
    write_kv(
        &path,
        &[
            ("id", &checkpoint.id),
            ("repo_id", &checkpoint.repo_id),
            ("vault_id", &checkpoint.vault_id),
            ("commit", &checkpoint.commit),
            ("parent", &checkpoint.parent),
            ("created_at", &checkpoint.created_at),
            ("status", &checkpoint.status),
            ("signature", &checkpoint.signature),
            ("signed_by", &checkpoint.signed_by),
            ("signed_at", &checkpoint.signed_at),
        ],
    )
}

pub fn read_session(path: &Path) -> Result<gitp2p_metadata::Session> {
    let map = read_kv(path)?;
    Ok(gitp2p_metadata::Session {
        id: field(&map, "id")?,
        peer_id: field(&map, "peer_id")?,
        repo_id: field(&map, "repo_id")?,
        checkpoint_id: field(&map, "checkpoint_id")?,
        direction: field(&map, "direction")?,
        state: field(&map, "state")?,
        encrypted: optional_field(&map, "encrypted"),
        created_at: field(&map, "created_at")?,
        phase: optional_field(&map, "phase"),
        transfer_artifact: optional_field(&map, "transfer_artifact"),
        bytes_transferred: optional_field(&map, "bytes_transferred"),
        transfer_offset: optional_field(&map, "transfer_offset"),
        signature: optional_field(&map, "signature"),
        signed_by: optional_field(&map, "signed_by"),
        signed_at: optional_field(&map, "signed_at"),
    })
}

pub fn write_session(app: &App, session: &gitp2p_metadata::Session) -> Result<()> {
    write_kv(
        &app.home.join("sessions").join(&session.id),
        &[
            ("id", &session.id),
            ("peer_id", &session.peer_id),
            ("repo_id", &session.repo_id),
            ("checkpoint_id", &session.checkpoint_id),
            ("direction", &session.direction),
            ("state", &session.state),
            ("encrypted", &session.encrypted),
            ("created_at", &session.created_at),
            ("phase", &session.phase),
            ("transfer_artifact", &session.transfer_artifact),
            ("bytes_transferred", &session.bytes_transferred),
            ("transfer_offset", &session.transfer_offset),
            ("signature", &session.signature),
            ("signed_by", &session.signed_by),
            ("signed_at", &session.signed_at),
        ],
    )
}

pub fn checkpoints_for_vault(vault: &Vault) -> Result<Vec<Checkpoint>> {
    let mut checkpoints = Vec::new();
    let dir = vault.path.join("metadata").join("checkpoints");
    if !dir.exists() {
        return Ok(checkpoints);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            checkpoints.push(read_checkpoint(&entry.path())?);
        }
    }
    checkpoints.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(checkpoints)
}

pub fn checkpoints_for_repo(app: &App, repo_id: &str) -> Result<Vec<Checkpoint>> {
    let mut checkpoints = Vec::new();
    for vault in app.all_vaults()? {
        checkpoints.extend(
            checkpoints_for_vault(&vault)?
                .into_iter()
                .filter(|checkpoint| checkpoint.repo_id == repo_id),
        );
    }
    checkpoints.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(checkpoints)
}

pub fn latest_checkpoint(app: &App, repo_id: &str) -> Result<Checkpoint> {
    checkpoints_for_repo(app, repo_id)?
        .into_iter()
        .last()
        .ok_or_else(|| AppError::new("repository has no checkpoints"))
}
