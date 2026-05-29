use gitp2p_metadata::{AuthDecision, Repo, RepoAction, Result, TRUST_ZONES};

pub fn is_valid_zone(zone: &str) -> bool {
    TRUST_ZONES.contains(&zone)
}

pub fn authorize_repo_action(
    repo: &Repo,
    action: RepoAction,
    requires_approval: bool,
    peer_trusted: bool,
) -> Result<AuthDecision> {
    let decision = match repo.trust_zone.as_str() {
        "trusted" => AuthDecision::Allow,
        "readonly" => match action {
            RepoAction::SyncPush => AuthDecision::Deny,
            _ => AuthDecision::Allow,
        },
        "protected" | "ai-generated" => match action {
            RepoAction::SyncPush => {
                if requires_approval {
                    AuthDecision::Allow
                } else {
                    AuthDecision::RequiresApproval
                }
            }
            _ => AuthDecision::Allow,
        },
        "experimental" => match action {
            RepoAction::Export => AuthDecision::Deny,
            RepoAction::SyncPush => {
                if requires_approval {
                    AuthDecision::Allow
                } else {
                    AuthDecision::RequiresApproval
                }
            }
            _ => AuthDecision::Allow,
        },
        "shared" => match action {
            RepoAction::SyncPush if !peer_trusted => AuthDecision::Deny,
            _ => AuthDecision::Allow,
        },
        "quarantined" => AuthDecision::Deny,
        other => {
            return Err(gitp2p_metadata::AppError::new(format!(
                "unknown trust zone '{other}'"
            )));
        }
    };
    Ok(decision)
}

pub fn enforce_repo_action(
    repo: &Repo,
    action: RepoAction,
    requires_approval: bool,
    peer_trusted: bool,
) -> Result<()> {
    match authorize_repo_action(repo, action, requires_approval, peer_trusted)? {
        AuthDecision::Allow => Ok(()),
        AuthDecision::RequiresApproval => Err(gitp2p_metadata::AppError::new(format!(
            "repository '{}' in zone '{}' requires approval; pass --requires-approval",
            repo.name, repo.trust_zone
        ))),
        AuthDecision::Deny => Err(gitp2p_metadata::AppError::new(format!(
            "action blocked for repository '{}' in trust zone '{}'",
            repo.name, repo.trust_zone
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gitp2p_metadata::Repo;
    use std::path::PathBuf;

    fn repo(zone: &str) -> Repo {
        Repo {
            id: "repo-1".into(),
            name: "demo".into(),
            path: PathBuf::from("/tmp/demo"),
            vault_id: "vault-1".into(),
            trust_zone: zone.into(),
            sync_state: "registered".into(),
            latest_checkpoint: String::new(),
            created_at: "0".into(),
        }
    }

    #[test]
    fn quarantined_blocks_checkpoint() {
        assert_eq!(
            authorize_repo_action(&repo("quarantined"), RepoAction::Checkpoint, false, false)
                .unwrap(),
            AuthDecision::Deny
        );
    }

    #[test]
    fn readonly_blocks_push() {
        assert_eq!(
            authorize_repo_action(&repo("readonly"), RepoAction::SyncPush, false, false).unwrap(),
            AuthDecision::Deny
        );
    }
}
