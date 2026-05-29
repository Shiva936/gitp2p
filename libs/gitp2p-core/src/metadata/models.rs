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

// --- v6 Autonomous Runtime ---

#[derive(Clone, Debug)]
pub struct RuntimePolicy {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub scope_vault: String,
    pub scope_repo: String,
    pub scope_domain: String,
    pub fields: String,
    pub active: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct RuntimeDecision {
    pub id: String,
    pub agent: String,
    pub phase: String,
    pub policy_id: String,
    pub action: String,
    pub expected_outcome: String,
    pub status: String,
    pub vault_id: String,
    pub repo_id: String,
    pub details: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct RuntimePlan {
    pub id: String,
    pub kind: String,
    pub decision_id: String,
    pub vault_id: String,
    pub repo_id: String,
    pub target_peer: String,
    pub action: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct HealthReport {
    pub id: String,
    pub vault_id: String,
    pub sync_score: u32,
    pub replica_score: u32,
    pub recovery_score: u32,
    pub trust_score: u32,
    pub topology_score: u32,
    pub risks: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct Explanation {
    pub id: String,
    pub decision_id: String,
    pub why: String,
    pub what: String,
    pub when_at: String,
    pub policy_source: String,
    pub expected_outcome: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Default)]
pub struct AutomationState {
    pub paused: String,
    pub last_tick: String,
}

#[derive(Clone, Debug)]
pub struct TrustRecommendation {
    pub id: String,
    pub peer_id: String,
    pub recommendation: String,
    pub reason: String,
    pub decision_id: String,
    pub created_at: String,
}

// --- v7 Enterprise ---

#[derive(Clone, Debug)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub owner_peer_id: String,
    pub members: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct Team {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub members: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct RoleAssignment {
    pub id: String,
    pub org_id: String,
    pub peer_id: String,
    pub role: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct GovernanceProposal {
    pub id: String,
    pub org_id: String,
    pub proposal_type: String,
    pub subject_id: String,
    pub state: String,
    pub proposer: String,
    pub reviewer: String,
    pub details: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub id: String,
    pub org_id: String,
    pub source: String,
    pub action: String,
    pub actor: String,
    pub details: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct ComplianceReport {
    pub id: String,
    pub org_id: String,
    pub status: String,
    pub findings: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct AdminDelegation {
    pub id: String,
    pub org_id: String,
    pub delegator: String,
    pub delegate: String,
    pub scope: String,
    pub state: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}

#[derive(Clone, Debug)]
pub struct OrgTrust {
    pub id: String,
    pub org_id: String,
    pub remote_org_id: String,
    pub state: String,
    pub created_at: String,
    pub signature: String,
    pub signed_by: String,
    pub signed_at: String,
}
