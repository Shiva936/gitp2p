use std::path::PathBuf;

pub const TRUST_ZONES: &[&str] = &[
    "trusted",
    "readonly",
    "experimental",
    "ai-generated",
    "protected",
    "shared",
    "quarantined",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoAction {
    Checkpoint,
    SyncPush,
    SyncPull,
    Export,
    Recover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthDecision {
    Allow,
    Deny,
    RequiresApproval,
}

#[derive(Clone, Debug)]
pub struct Identity {
    pub peer_id: String,
    pub public_key: String,
    pub private_key: String,
    pub fingerprint: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct Vault {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct Repo {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub vault_id: String,
    pub trust_zone: String,
    pub sync_state: String,
    pub latest_checkpoint: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct Checkpoint {
    pub id: String,
    pub repo_id: String,
    pub vault_id: String,
    pub commit: String,
    pub parent: String,
    pub created_at: String,
    pub status: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub id: String,
    pub public_key: String,
    pub home: PathBuf,
    pub trust_state: String,
    pub capabilities: String,
    pub vaults: String,
    pub discovered_at: String,
    pub listen_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    Discovered,
    Authenticated,
    Negotiating,
    Transferring,
    Validating,
    Propagating,
    Complete,
    Failed,
}

impl SessionPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Authenticated => "authenticated",
            Self::Negotiating => "negotiating",
            Self::Transferring => "transferring",
            Self::Validating => "validating",
            Self::Propagating => "propagating",
            Self::Complete => "complete",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "discovered" => Some(Self::Discovered),
            "authenticated" => Some(Self::Authenticated),
            "negotiating" => Some(Self::Negotiating),
            "transferring" => Some(Self::Transferring),
            "validating" => Some(Self::Validating),
            "propagating" => Some(Self::Propagating),
            "complete" => Some(Self::Complete),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Session {
    pub id: String,
    pub peer_id: String,
    pub repo_id: String,
    pub checkpoint_id: String,
    pub direction: String,
    pub state: String,
    pub encrypted: String,
    pub created_at: String,
    pub phase: String,
    pub transfer_artifact: String,
    pub bytes_transferred: String,
    pub transfer_offset: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub require_approval_for_zones: String,
    pub allowed_peer_ids: String,
    pub blocked_peer_ids: String,
    pub retention_max_checkpoints: String,
    pub retention_max_age_days: String,
    pub protected_checkpoint_ids: String,
}

impl Policy {
    pub fn fields(&self) -> Vec<(&str, &str)> {
        vec![
            (
                "require_approval_for_zones",
                &self.require_approval_for_zones,
            ),
            ("allowed_peer_ids", &self.allowed_peer_ids),
            ("blocked_peer_ids", &self.blocked_peer_ids),
            (
                "retention_max_checkpoints",
                &self.retention_max_checkpoints,
            ),
            ("retention_max_age_days", &self.retention_max_age_days),
            (
                "protected_checkpoint_ids",
                &self.protected_checkpoint_ids,
            ),
        ]
    }
}

#[derive(Clone, Debug, Default)]
pub struct DomainPolicy {
    pub trust_policy: String,
    pub routing_policy: String,
    pub peering_policy: String,
}

impl DomainPolicy {
    pub fn fields(&self) -> Vec<(&str, &str)> {
        vec![
            ("trust_policy", &self.trust_policy),
            ("routing_policy", &self.routing_policy),
            ("peering_policy", &self.peering_policy),
        ]
    }
}

#[derive(Clone, Debug)]
pub struct FederationDomain {
    pub id: String,
    pub name: String,
    pub owner_peer_id: String,
    pub trust_policy: String,
    pub routing_policy: String,
    pub peering_policy: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct Gateway {
    pub id: String,
    pub domain_id: String,
    pub listen_addr: String,
    pub listen_port: u16,
    pub state: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct Peering {
    pub id: String,
    pub local_domain_id: String,
    pub remote_domain_id: String,
    pub local_gateway_id: String,
    pub remote_gateway_id: String,
    pub state: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct TrustDelegation {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub delegation_type: String,
    pub scope: String,
    pub parent_id: String,
    pub state: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct GlobalRoute {
    pub id: String,
    pub destination: String,
    pub hops: String,
    pub gateway_hops: String,
    pub cost: u32,
    pub state: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct SyncPath {
    pub session_id: String,
    pub repo_id: String,
    pub route_id: String,
    pub path: String,
    pub phase: String,
}
