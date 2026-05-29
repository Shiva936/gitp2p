mod extended;
#[cfg(any(feature = "runtime", feature = "enterprise"))]
mod runtime_handlers;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use gitp2p_content::{export_bundle, import_bundle, ExportOptions};
use gitp2p_core::VERSION;
use gitp2p_core::util::{count_files, empty_dash};
use gitp2p_sync::{
    best_checkpoint_peers, doctor_repo, recover_from_best_peer, recover_from_peer, recover_local,
    discover_filesystem, discover_lan, advertise_lan, list_inflight_sessions, sync_local,
    sync_to_peer,
};
use gitp2p_core::trust::{set_policy_field, show_policy, write_peer};
use gitp2p_core::{
    checkpoints_for_repo, checkpoints_for_vault, create_checkpoint, create_vault, delete_vault,
    prune_checkpoints, add_repo, remove_repo, App,
};
use gitp2p_core::trust::merged_policy;

#[derive(Parser)]
#[command(name = "gitp2p", version = VERSION, about = "Trusted local-first Git vaults")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Identity {
        #[command(subcommand)]
        command: IdentityCommands,
    },
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    Repo {
        #[command(subcommand)]
        command: RepoCommands,
    },
    Checkpoint {
        repo: Option<String>,
        #[arg(long)]
        enforce_retention: bool,
        #[command(subcommand)]
        command: Option<CheckpointCommands>,
    },
    Recover {
        repo: String,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        checkpoint: Option<String>,
        #[arg(long)]
        target: Option<PathBuf>,
        #[arg(long)]
        auto_recover: bool,
        #[arg(long)]
        offline: Option<PathBuf>,
        #[arg(long)]
        network: Option<String>,
        #[command(subcommand)]
        command: Option<RecoverCommands>,
    },
    Sync {
        repo: Option<String>,
        #[arg(long)]
        peer: Option<String>,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        requires_approval: bool,
        #[arg(long)]
        enforce_retention: bool,
        #[command(subcommand)]
        command: Option<SyncSubcommands>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        trailing: Vec<String>,
    },
    Peers {
        #[command(subcommand)]
        command: PeersCommands,
    },
    Trust {
        #[command(subcommand)]
        command: TrustCommands,
    },
    Export {
        repo: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Import {
        bundle: PathBuf,
        #[arg(long)]
        vault: Option<String>,
    },
    Bundle {
        #[command(subcommand)]
        command: BundleCommands,
    },
    Lineage {
        #[command(subcommand)]
        command: LineageCommands,
    },
    Manifest {
        #[command(subcommand)]
        command: ManifestCommands,
    },
    Cas {
        #[command(subcommand)]
        command: CasCommands,
    },
    Merkle {
        #[command(subcommand)]
        command: MerkleCommands,
    },
    #[cfg(feature = "federation")]
    Mesh {
        #[command(subcommand)]
        command: MeshCommands,
    },
    #[cfg(feature = "federation")]
    Route {
        #[command(subcommand)]
        command: RouteCommands,
    },
    #[cfg(feature = "federation")]
    Relay {
        #[command(subcommand)]
        command: RelayCommands,
    },
    #[cfg(feature = "federation")]
    Topology {
        #[command(subcommand)]
        command: TopologyCommands,
    },
    Id {
        #[command(subcommand)]
        command: IdCommands,
    },
    Media {
        #[command(subcommand)]
        command: MediaCommands,
    },
    #[cfg(feature = "federation")]
    Domain {
        #[command(subcommand)]
        command: DomainCommands,
    },
    #[cfg(feature = "federation")]
    Gateway {
        #[command(subcommand)]
        command: GatewayCommands,
    },
    #[cfg(feature = "federation")]
    PeerDomain {
        #[command(subcommand)]
        command: PeerDomainCommands,
    },
    #[cfg(feature = "federation")]
    Discover {
        #[command(subcommand)]
        command: DiscoverCommands,
    },
    Verify {
        #[command(subcommand)]
        command: VerifyCommands,
    },
    #[cfg(feature = "runtime")]
    Policy {
        #[command(subcommand)]
        command: RuntimePolicyCommands,
    },
    #[cfg(feature = "runtime")]
    Health {
        #[command(subcommand)]
        command: HealthCommands,
    },
    #[cfg(feature = "runtime")]
    Automation {
        #[command(subcommand)]
        command: AutomationCommands,
    },
    #[cfg(feature = "runtime")]
    Explain {
        #[command(subcommand)]
        command: ExplainCommands,
    },
    #[cfg(feature = "runtime")]
    Replica {
        #[command(subcommand)]
        command: ReplicaCommands,
    },
    #[cfg(feature = "runtime")]
    Recovery {
        #[command(subcommand)]
        command: RecoveryCommands,
    },
    #[cfg(feature = "runtime")]
    Replay {
        #[command(subcommand)]
        command: ReplayCommands,
    },
    #[cfg(feature = "enterprise")]
    Org {
        #[command(subcommand)]
        command: OrgCommands,
    },
    #[cfg(feature = "enterprise")]
    Team {
        #[command(subcommand)]
        command: TeamCommands,
    },
    #[cfg(feature = "enterprise")]
    Role {
        #[command(subcommand)]
        command: RoleCommands,
    },
    #[cfg(feature = "enterprise")]
    Governance {
        #[command(subcommand)]
        command: GovernanceCommands,
    },
    #[cfg(feature = "enterprise")]
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    #[cfg(feature = "enterprise")]
    Compliance {
        #[command(subcommand)]
        command: ComplianceCommands,
    },
    #[cfg(feature = "enterprise")]
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
    #[cfg(feature = "enterprise")]
    Visibility {
        #[command(subcommand)]
        command: VisibilityCommands,
    },
    Reconcile {
        #[command(subcommand)]
        command: ReconcileCommands,
    },
    Sign {
        #[arg(long)]
        payload: Option<String>,
        #[arg(long)]
        checkpoint: Option<String>,
    },
    Signature {
        #[command(subcommand)]
        command: SignatureCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    Show,
    Inspect,
    Create,
    Export { dest: PathBuf },
    Import { source: PathBuf },
}

#[derive(Subcommand)]
enum VaultCommands {
    Create { name: String },
    List,
    Info { name_or_id: String },
    Shared,
    Delete {
        name_or_id: String,
        #[arg(long)]
        yes: bool,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
    Export {
        vault: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    ImportPackage {
        package: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    Join {
        package: PathBuf,
    },
    Replicas {
        vault: String,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    Show {
        vault: String,
        #[arg(long)]
        repo: Option<String>,
    },
    Set {
        vault: String,
        field: String,
        value: String,
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
enum RepoCommands {
    Add {
        vault: String,
        path: Option<String>,
        #[arg(long)]
        zone: Option<String>,
    },
    List,
    Info { name_or_id: String },
    Remove {
        name_or_id: String,
        #[arg(long)]
        yes: bool,
    },
    Doctor { name_or_id: String },
}

#[derive(Subcommand)]
enum CheckpointCommands {
    Create {
        repo: Option<String>,
        #[arg(long)]
        enforce_retention: bool,
    },
    List { repo: String },
    Info { checkpoint_id: String },
    Peers {
        #[arg(long)]
        best: bool,
    },
    Verify { checkpoint_id: String },
    Prune {
        repo: String,
        #[arg(long)]
        keep: Option<usize>,
        #[arg(long)]
        older_than: Option<u64>,
        #[arg(long)]
        dry_run: bool,
    },
    #[cfg(feature = "runtime")]
    Explain {
        #[arg(long)]
        decision: Option<String>,
    },
}

#[derive(Subcommand)]
enum SyncSubcommands {
    Status { repo: Option<String> },
    #[cfg(feature = "federation")]
    Inspect { session_id: Option<String> },
    #[cfg(feature = "runtime")]
    Plan {
        #[arg(long, default_value = "default")]
        vault: String,
    },
    #[cfg(feature = "runtime")]
    Explain {
        #[arg(long)]
        decision: Option<String>,
    },
}

#[derive(Subcommand)]
enum PeersCommands {
    Discover {
        #[arg(long)]
        lan: bool,
        #[arg(long, default_value_t = 3)]
        timeout: u64,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        homes: Vec<String>,
    },
    List,
    Inspect { peer_id: String },
    Verify { peer_id: String },
    Listen,
}

#[derive(Subcommand)]
enum TrustCommands {
    Add {
        peer_id: String,
        #[arg(long)]
        role: Option<String>,
    },
    Revoke { peer_id: String },
    Request { peer_id: String },
    Graph,
    Requests,
    Delegate {
        target: String,
        #[arg(long, default_value = "peer")]
        r#type: String,
        #[arg(long, default_value = "sync")]
        scope: String,
    },
    RevokeDelegation { id: String },
    InspectDelegation {
        #[arg(long)]
        chain: bool,
        root: Option<String>,
    },
    #[cfg(feature = "runtime")]
    Recommend,
    #[cfg(feature = "runtime")]
    Explain {
        #[arg(long)]
        decision: Option<String>,
    },
    Export {
        dest: PathBuf,
    },
    Validate {
        source: PathBuf,
    },
}

#[derive(Subcommand)]
enum ReconcileCommands {
    Run { repo: String },
    History {
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
enum SignatureCommands {
    Verify {
        signature: String,
        #[arg(long)]
        payload: Option<String>,
        #[arg(long)]
        public_key: Option<String>,
        #[arg(long)]
        checkpoint: Option<String>,
    },
}

#[derive(Subcommand)]
enum BundleCommands {
    Create {
        repo: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        structured: bool,
        #[arg(long)]
        encrypt: bool,
        #[arg(long)]
        since: Option<String>,
    },
    Import {
        bundle: PathBuf,
        #[arg(long)]
        vault: Option<String>,
    },
    Validate { bundle: PathBuf },
}

#[derive(Subcommand)]
enum LineageCommands {
    Inspect { checkpoint_id: String },
    Hash { checkpoint_id: String },
    Verify {
        checkpoint_id: String,
        hash: String,
    },
}

#[derive(Subcommand)]
enum ManifestCommands {
    Inspect { path: PathBuf },
    Verify { path: PathBuf },
}

#[derive(Subcommand)]
enum CasCommands {
    Store { path: PathBuf },
    Load {
        chunk_id: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    Verify { chunk_id: String },
}

#[derive(Subcommand)]
enum MerkleCommands {
    Verify {
        #[arg(num_args = 1..)]
        leaves: Vec<String>,
    },
}

#[cfg(feature = "federation")]
#[derive(Subcommand)]
enum MeshCommands {
    Reconcile { repo: String },
}

#[derive(Subcommand)]
enum RouteCommands {
    Inspect {
        #[arg(long)]
        destination: Option<String>,
        #[arg(long)]
        global: bool,
    },
    Verify { route_id: String },
}

#[derive(Subcommand)]
enum RelayCommands {
    Enable,
    Disable,
    Status,
}

#[derive(Subcommand)]
enum TopologyCommands {
    Peers,
    Trust,
    Routes,
    Vaults,
    Summary,
}

#[derive(Subcommand)]
enum IdCommands {
    Create,
    Inspect,
    Export { dest: PathBuf },
    Import { source: PathBuf },
}

#[derive(Subcommand)]
enum MediaCommands {
    Export {
        source: PathBuf,
        #[arg(long)]
        media: PathBuf,
    },
    Import {
        #[arg(long)]
        media: PathBuf,
        name: String,
    },
}

#[derive(Subcommand)]
enum DomainCommands {
    Create { name: String },
    Inspect { domain_id: Option<String> },
    Policy {
        #[command(subcommand)]
        command: DomainPolicyCommands,
    },
    Delete {
        domain_id: String,
        #[arg(long)]
        yes: bool,
    },
    Migrate {
        #[arg(long)]
        to: String,
        #[arg(long)]
        vault: Option<String>,
    },
}

#[derive(Subcommand)]
enum DomainPolicyCommands {
    Set {
        domain_id: String,
        field: String,
        value: String,
    },
}

#[derive(Subcommand)]
enum GatewayCommands {
    Create {
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        listen: Option<String>,
    },
    Inspect { gateway_id: Option<String> },
}

#[derive(Subcommand)]
enum PeerDomainCommands {
    Connect {
        remote_domain: String,
        #[arg(long)]
        gateway: Option<String>,
    },
    Revoke { remote_domain: String },
    Inspect { remote_domain: Option<String> },
}

#[derive(Subcommand)]
enum DiscoverCommands {
    Domains,
    Gateways,
    Vaults,
    Replicas {
        #[arg(long)]
        repo: Option<String>,
    },
}

#[derive(Subcommand)]
enum RecoverCommands {
    #[cfg(feature = "federation")]
    Global {
        repo: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        target: Option<PathBuf>,
    },
    #[cfg(feature = "federation")]
    Sources { repo: String },
}

#[derive(Subcommand)]
enum VerifyCommands {
    #[cfg(feature = "federation")]
    Domain { id: String },
    #[cfg(feature = "federation")]
    Gateway { id: String },
    #[cfg(feature = "federation")]
    Peering { remote_domain: String },
    Delegation { id: String },
    #[cfg(feature = "federation")]
    Route { route_id: String },
    #[cfg(feature = "runtime")]
    Policy { id: String },
}

#[derive(Subcommand)]
enum RuntimePolicyCommands {
    Create {
        name: String,
        kind: String,
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long, default_value = "")]
        fields: String,
    },
    Inspect { reference: Option<String> },
    Update {
        reference: String,
        #[arg(long)]
        fields: Option<String>,
        #[arg(long)]
        active: Option<String>,
    },
    Delete { reference: String },
    History {
        #[arg(long)]
        org: Option<String>,
    },
}

#[derive(Subcommand)]
enum HealthCommands {
    Inspect {
        #[arg(long, default_value = "default")]
        vault: String,
    },
}

#[derive(Subcommand)]
enum AutomationCommands {
    Run {
        #[arg(long, default_value = "default")]
        vault: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        org: Option<String>,
    },
    Pause,
    Resume,
}

#[derive(Subcommand)]
enum ExplainCommands {
    Decision {
        #[arg(long)]
        id: Option<String>,
    },
}

#[cfg(feature = "runtime")]
#[derive(Subcommand)]
enum ReplicaCommands {
    Explain {
        #[arg(long)]
        decision: Option<String>,
    },
}

#[cfg(feature = "runtime")]
#[derive(Subcommand)]
enum RecoveryCommands {
    Plan {
        #[arg(long, default_value = "default")]
        vault: String,
    },
}

#[cfg(feature = "runtime")]
#[derive(Subcommand)]
enum ReplayCommands {
    Decision {
        id: String,
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum OrgCommands {
    Create { name: String },
    Inspect { reference: Option<String> },
    Update {
        reference: String,
        #[arg(long)]
        name: Option<String>,
    },
    Member {
        #[command(subcommand)]
        command: OrgMemberCommands,
    },
    Trust {
        #[command(subcommand)]
        command: OrgTrustCommands,
    },
}

#[derive(Subcommand)]
enum OrgMemberCommands {
    Add { org: String, peer_id: String },
    Remove { org: String, peer_id: String },
}

#[derive(Subcommand)]
enum OrgTrustCommands {
    Establish { org: String, remote_org: String },
    Inspect {
        org: String,
        #[arg(long)]
        remote: Option<String>,
    },
    Revoke { org: String, remote_org: String },
}

#[derive(Subcommand)]
enum TeamCommands {
    Create { org: String, name: String },
    Inspect {
        reference: Option<String>,
        #[arg(long)]
        org: Option<String>,
    },
    Member {
        team: String,
        peer_id: String,
    },
}

#[derive(Subcommand)]
enum RoleCommands {
    Assign {
        org: String,
        peer_id: String,
        role: String,
    },
    Revoke { org: String, peer_id: String },
    Inspect { org: String },
}

#[derive(Subcommand)]
enum GovernanceCommands {
    Propose {
        org: String,
        #[arg(long)]
        r#type: String,
        subject_id: String,
        details: String,
    },
    Review { id: String },
    Approve { org: String, id: String },
    Reject { id: String },
    Inspect { org: String },
}

#[derive(Subcommand)]
enum AuditCommands {
    Search {
        #[arg(long)]
        org: Option<String>,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        action: Option<String>,
    },
    Export {
        #[arg(long)]
        org: Option<String>,
    },
}

#[derive(Subcommand)]
enum ComplianceCommands {
    Inspect { org: String },
    Report { org: String },
}

#[derive(Subcommand)]
enum AdminCommands {
    Delegate {
        org: String,
        delegate: String,
        #[arg(long, default_value = "administration")]
        scope: String,
    },
    Revoke { org: String, delegate: String },
    Inspect { org: String },
}

#[derive(Subcommand)]
enum VisibilityCommands {
    Report { org: String },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> gitp2p_core::Result<()> {
    let cli = Cli::parse();
    let app = App::load()?;
    app.ensure_home()?;

    let skip_identity = matches!(
        cli.command,
        Commands::Id {
            command: IdCommands::Create
        } | Commands::Identity {
            command: IdentityCommands::Create
        }
    );
    if !skip_identity {
        app.ensure_identity()?;
    }

    match cli.command {
        Commands::Identity { command } => match command {
            IdentityCommands::Show | IdentityCommands::Inspect => {
                let identity = app.ensure_identity()?;
                println!("peer_id: {}", identity.peer_id);
                println!("fingerprint: {}", identity.fingerprint);
                println!("public_key: {}", identity.public_key);
                Ok(())
            }
            IdentityCommands::Create => extended::cmd_id_create(&app),
            IdentityCommands::Export { dest } => extended::cmd_id_export(&app, dest),
            IdentityCommands::Import { source } => extended::cmd_id_import(&app, source),
        },
        Commands::Vault { command } => match command {
            VaultCommands::Create { name } => {
                let vault = create_vault(&app, &name)?;
                println!("vault created");
                println!("  id: {}", vault.id);
                println!("  name: {}", vault.name);
                println!("  path: {}", vault.path.display());
                Ok(())
            }
            VaultCommands::List => {
                let vaults = app.all_vaults()?;
                if vaults.is_empty() {
                    println!("no vaults");
                    return Ok(());
                }
                println!("id\tname\trepositories\tcheckpoints\ttrust");
                for vault in vaults {
                    let repo_count = count_files(vault.path.join("metadata").join("repos"))?;
                    let cp_count = count_files(vault.path.join("metadata").join("checkpoints"))?;
                    println!(
                        "{}\t{}\t{}\t{}\tsovereign-local",
                        vault.id, vault.name, repo_count, cp_count
                    );
                }
                Ok(())
            }
            VaultCommands::Info { name_or_id } => {
                let vault = app.find_vault(&name_or_id)?;
                println!("vault {}", vault.name);
                println!("  id: {}", vault.id);
                println!("  path: {}", vault.path.display());
                println!("  created_at: {}", vault.created_at);
                println!("repositories:");
                for repo in app
                    .all_repos()?
                    .into_iter()
                    .filter(|repo| repo.vault_id == vault.id)
                {
                    println!("  {} ({}) {}", repo.name, repo.id, repo.sync_state);
                }
                println!("checkpoints:");
                for checkpoint in checkpoints_for_vault(&vault)? {
                    println!(
                        "  {} repo={} commit={}",
                        checkpoint.id, checkpoint.repo_id, checkpoint.commit
                    );
                }
                Ok(())
            }
            VaultCommands::Shared => {
                let vaults = app.all_vaults()?;
                if vaults.is_empty() {
                    println!("no shared vaults");
                    return Ok(());
                }
                println!("vault\tpeers\treplication_state\tcheckpoints");
                for vault in vaults {
                    let peers = count_files(vault.path.join("replication"))?;
                    let checkpoints = count_files(vault.path.join("metadata").join("checkpoints"))?;
                    let state = if peers == 0 { "local-only" } else { "replicated" };
                    println!("{}\t{}\t{}\t{}", vault.name, peers, state, checkpoints);
                }
                Ok(())
            }
            VaultCommands::Delete { name_or_id, yes } => {
                let vault = delete_vault(&app, &name_or_id, yes)?;
                println!("vault deleted: {}", vault.name);
                Ok(())
            }
            VaultCommands::Policy { command } => match command {
                PolicyCommands::Show { vault, repo } => {
                    let vault = app.find_vault(&vault)?;
                    let policy = show_policy(&vault, repo.as_deref())?;
                    for (key, value) in policy.fields() {
                        if !value.is_empty() {
                            println!("{key}={value}");
                        }
                    }
                    Ok(())
                }
                PolicyCommands::Set {
                    vault,
                    field,
                    value,
                    repo,
                } => {
                    let vault = app.find_vault(&vault)?;
                    set_policy_field(&vault, repo.as_deref(), &field, &value)?;
                    println!("policy updated");
                    Ok(())
                }
            },
            VaultCommands::Export { vault, output } => extended::cmd_vault_export(&app, &vault, output),
            VaultCommands::ImportPackage { package, name } => {
                extended::cmd_vault_import(&app, package, name)
            }
            VaultCommands::Join { package } => extended::cmd_vault_join(&app, package),
            VaultCommands::Replicas { vault } => extended::cmd_vault_replicas(&app, &vault),
        },
        Commands::Repo { command } => match command {
            RepoCommands::Add { vault, path, zone } => {
                let vault = app.find_vault(&vault)?;
                let repo = add_repo(
                    &app,
                    &vault,
                    path,
                    zone.as_deref().unwrap_or("trusted"),
                )?;
                println!("repository registered");
                println!("  id: {}", repo.id);
                println!("  name: {}", repo.name);
                println!("  vault: {}", vault.name);
                println!("  path: {}", repo.path.display());
                Ok(())
            }
            RepoCommands::List => {
                let repos = app.all_repos()?;
                if repos.is_empty() {
                    println!("no repositories");
                    return Ok(());
                }
                println!("id\tname\tvault\tstatus\tlatest_checkpoint\tpath");
                for repo in repos {
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{}",
                        repo.id,
                        repo.name,
                        repo.vault_id,
                        repo.sync_state,
                        empty_dash(&repo.latest_checkpoint),
                        repo.path.display()
                    );
                }
                Ok(())
            }
            RepoCommands::Info { name_or_id } => {
                let repo = app.find_repo(Some(&name_or_id))?;
                println!("repository {}", repo.name);
                println!("  trust_zone: {}", repo.trust_zone);
                println!("  sync_state: {}", repo.sync_state);
                for checkpoint in checkpoints_for_repo(&app, &repo.id)? {
                    println!("  checkpoint {} {}", checkpoint.id, checkpoint.commit);
                }
                Ok(())
            }
            RepoCommands::Remove { name_or_id, yes } => {
                let repo = app.find_repo(Some(&name_or_id))?;
                remove_repo(&app, &repo, yes)?;
                println!("repository untracked: {}", repo.name);
                Ok(())
            }
            RepoCommands::Doctor { name_or_id } => {
                let repo = app.find_repo(Some(&name_or_id))?;
                let report = doctor_repo(&repo)?;
                println!("{}", report.message);
                if report.healthy {
                    Ok(())
                } else {
                    Err(gitp2p_core::AppError::new("repository needs recovery"))
                }
            }
        },
        Commands::Checkpoint {
            repo: top_repo,
            enforce_retention: top_enforce,
            command,
        } => match command {
            None => {
                let checkpoint = create_checkpoint(
                    &app,
                    top_repo.as_deref(),
                    top_enforce,
                    false,
                    false,
                )?;
                println!("checkpoint created");
                println!("  id: {}", checkpoint.id);
                println!("  commit: {}", checkpoint.commit);
                Ok(())
            }
            Some(CheckpointCommands::Create { repo, enforce_retention }) => {
                let repo = repo.or(top_repo);
                let enforce_retention = enforce_retention || top_enforce;
                let checkpoint = create_checkpoint(
                    &app,
                    repo.as_deref(),
                    enforce_retention,
                    false,
                    false,
                )?;
                println!("checkpoint created");
                println!("  id: {}", checkpoint.id);
                println!("  commit: {}", checkpoint.commit);
                Ok(())
            }
            Some(CheckpointCommands::List { repo }) => {
                let repo = app.find_repo(Some(&repo))?;
                for checkpoint in checkpoints_for_repo(&app, &repo.id)? {
                    println!(
                        "{}\t{}\t{}\t{}",
                        checkpoint.id, checkpoint.created_at, checkpoint.status, checkpoint.commit
                    );
                }
                Ok(())
            }
            Some(CheckpointCommands::Info { checkpoint_id }) => {
                let (_, repo, checkpoint) = app.find_checkpoint(&checkpoint_id)?;
                println!("checkpoint {}", checkpoint.id);
                println!("  repository: {} ({})", repo.name, repo.id);
                println!("  commit: {}", checkpoint.commit);
                Ok(())
            }
            Some(CheckpointCommands::Verify { checkpoint_id }) => {
                extended::cmd_checkpoint_verify(&app, &checkpoint_id)
            }
            Some(CheckpointCommands::Peers { best }) => {
                if best {
                    for (peer, repo, checkpoint) in best_checkpoint_peers(&app)? {
                        println!("{peer}\t{repo}\t{checkpoint}");
                    }
                    return Ok(());
                }
                println!("peer_id\trepo_id\tcheckpoint\tstate\tlineage\tpropagation");
                for vault in app.all_vaults()? {
                    let dir = vault.path.join("replication");
                    if !dir.exists() {
                        continue;
                    }
                    for entry in std::fs::read_dir(dir)? {
                        let entry = entry?;
                        if entry.file_type()?.is_file() {
                            let map = gitp2p_core::read_kv(&entry.path())?;
                            println!(
                                "{}\t{}\t{}\t{}\t{}\t{}",
                                gitp2p_core::optional_field(&map, "peer_id"),
                                gitp2p_core::optional_field(&map, "repo_id"),
                                gitp2p_core::optional_field(&map, "checkpoint_id"),
                                gitp2p_core::optional_field(&map, "state"),
                                gitp2p_core::optional_field(&map, "checkpoint_lineage"),
                                gitp2p_core::optional_field(&map, "propagation_state"),
                            );
                        }
                    }
                }
                Ok(())
            }
            Some(CheckpointCommands::Prune {
                repo,
                keep,
                older_than,
                dry_run,
            }) => {
                let repo = app.find_repo(Some(&repo))?;
                let vault = app.find_vault(&repo.vault_id)?;
                let policy = merged_policy(&vault, Some(&repo.id))?;
                let report = prune_checkpoints(&app, &repo, &policy, keep, older_than, dry_run)?;
                println!("removed: {}", report.removed.join(","));
                println!("kept: {}", report.kept.join(","));
                Ok(())
            }
            #[cfg(feature = "runtime")]
            Some(CheckpointCommands::Explain { decision }) => {
                runtime_handlers::cmd_checkpoint_explain(&app, decision)
            }
        },
        Commands::Recover {
            repo,
            peer,
            checkpoint,
            target,
            auto_recover,
            offline,
            network: network_dest,
            command: recover_command,
        } => {
            #[cfg(not(feature = "federation"))]
            let _ = (&network_dest, &recover_command);
            #[cfg(feature = "federation")]
            if let Some(RecoverCommands::Global {
                repo,
                domain,
                target,
            }) = recover_command
            {
                return extended::cmd_recover_global(&app, &repo, domain, target);
            }
            #[cfg(feature = "federation")]
            if let Some(RecoverCommands::Sources { repo }) = recover_command {
                return extended::cmd_recover_sources(&app, &repo);
            }
            if let Some(bundle) = offline {
                return extended::cmd_recover_offline(&app, bundle, None);
            }
            #[cfg(feature = "federation")]
            if let Some(dest) = network_dest {
                return extended::cmd_recover_network(&app, &repo, &dest);
            }
            #[cfg(all(not(feature = "federation"), feature = "runtime"))]
            if network_dest.is_some() {
                return Err(gitp2p_core::AppError::new("federation feature required for network recovery"));
            }
            let repo = app.find_repo(Some(&repo))?;
            if let Some(peer_spec) = peer {
                if peer_spec == "auto" || peer_spec.contains(',') {
                    return recover_from_best_peer(
                        &app,
                        &repo,
                        &peer_spec,
                        checkpoint.as_deref(),
                        target,
                    );
                }
                return recover_from_peer(
                    &app,
                    &repo,
                    &peer_spec,
                    checkpoint.as_deref(),
                    target,
                );
            }
            let cp = checkpoint
                .as_deref()
                .map(|id| app.find_checkpoint(id).map(|(_, _, cp)| cp))
                .transpose()?;
            recover_local(&app, &repo, cp.as_ref(), target, auto_recover)
        }
        Commands::Sync {
            repo,
            peer,
            domain: sync_domain,
            requires_approval,
            enforce_retention,
            command: sync_command,
            trailing,
        } => {
            #[cfg(not(feature = "federation"))]
            let _ = (&sync_domain, &sync_command);
            #[cfg(feature = "federation")]
            if let Some(SyncSubcommands::Inspect { session_id }) = sync_command {
                return extended::cmd_sync_inspect(&app, session_id);
            }
            if let Some(SyncSubcommands::Status { repo }) = sync_command {
                for session in list_inflight_sessions(&app, repo.as_deref())? {
                    println!(
                        "{} peer={} repo={} phase={} artifact={}",
                        session.id,
                        session.peer_id,
                        session.repo_id,
                        session.phase,
                        empty_dash(&session.transfer_artifact)
                    );
                }
                return Ok(());
            }
            #[cfg(feature = "runtime")]
            if let Some(SyncSubcommands::Plan { vault }) = sync_command {
                return runtime_handlers::cmd_sync_plan(&app, &vault);
            }
            #[cfg(feature = "runtime")]
            if let Some(SyncSubcommands::Explain { decision }) = sync_command {
                return runtime_handlers::cmd_sync_explain(&app, decision);
            }
            #[cfg(feature = "federation")]
            if let Some(domain_id) = sync_domain {
                return extended::cmd_global_sync(
                    &app,
                    repo,
                    &domain_id,
                    requires_approval,
                    enforce_retention,
                );
            }
            let mut peer_id = peer.map(|p| {
                p.strip_prefix("peer://")
                    .unwrap_or(p.as_str())
                    .to_string()
            });
            if peer_id.is_none() {
                for arg in &trailing {
                    if arg.starts_with("peer://") {
                        peer_id = Some(arg.trim_start_matches("peer://").to_string());
                    } else if repo.is_none() {
                        // handled below via repo ref
                    }
                }
            }
            let repo_ref = repo.or_else(|| {
                trailing
                    .iter()
                    .find(|arg| !arg.starts_with("peer://"))
                    .cloned()
            });
            if let Some(peer_id) = peer_id {
                let session = sync_to_peer(
                    &app,
                    repo_ref.as_deref(),
                    &peer_id,
                    requires_approval,
                    enforce_retention,
                )?;
                println!("peer synchronization complete");
                println!("  session: {}", session.id);
                println!("  encrypted: {}", session.encrypted);
                return Ok(());
            }
            let checkpoint = sync_local(&app, repo_ref.as_deref(), enforce_retention)?;
            println!("local synchronization complete");
            println!("  checkpoint: {}", checkpoint.id);
            Ok(())
        }
        Commands::Peers { command } => match command {
            PeersCommands::Discover { lan, timeout, homes } => {
                let identity = app.ensure_identity()?;
                println!("peer_id\ttrust\tconnectivity\tvaults\thome");
                println!(
                    "{}\tlocal-trusted\tlocal\t{}\t{}",
                    identity.peer_id,
                    app.all_vaults()?.len(),
                    app.home.display()
                );
                let mut discovered = Vec::new();
                if lan {
                    discovered.extend(discover_lan(&app, timeout)?);
                }
                let homes: Vec<PathBuf> = homes.into_iter().map(PathBuf::from).collect();
                discovered.extend(discover_filesystem(&app, &homes)?);
                for peer in discovered {
                    println!(
                        "{}\t{}\tdiscovered\t{}\t{}",
                        peer.id,
                        peer.trust_state,
                        empty_dash(&peer.vaults),
                        if peer.home.as_os_str().is_empty() {
                            format!("lan:{}", peer.listen_port)
                        } else {
                            peer.home.display().to_string()
                        }
                    );
                }
                Ok(())
            }
            PeersCommands::List => {
                let peers = app.all_peers()?;
                println!("peer_id\ttrust\tcapabilities\tvaults");
                for peer in peers {
                    println!(
                        "{}\t{}\t{}\t{}",
                        peer.id,
                        peer.trust_state,
                        peer.capabilities,
                        empty_dash(&peer.vaults)
                    );
                }
                Ok(())
            }
            PeersCommands::Inspect { peer_id } => {
                let peer = app.find_peer(&peer_id)?;
                println!("peer {}", peer.id);
                println!("  public_key: {}", peer.public_key);
                println!("  trust_state: {}", peer.trust_state);
                println!("  listen_port: {}", peer.listen_port);
                println!("  capabilities: {}", peer.capabilities);
                println!("  vaults: {}", empty_dash(&peer.vaults));
                println!("replication history:");
                extended::cmd_replication_history(&app, Some(peer_id))?;
                Ok(())
            }
            PeersCommands::Verify { peer_id } => extended::cmd_peer_verify(&app, &peer_id),
            PeersCommands::Listen => advertise_lan(&app),
        },
        Commands::Trust { command } => match command {
            TrustCommands::Add { peer_id, role } => {
                let mut peer = app.find_peer(&peer_id)?;
                peer.trust_state = role.unwrap_or_else(|| "trusted".to_string());
                write_peer(&app.home, &peer)?;
                println!("peer added: {}", peer.id);
                Ok(())
            }
            TrustCommands::Revoke { peer_id } => {
                let mut peer = app.find_peer(&peer_id)?;
                peer.trust_state = "revoked".to_string();
                write_peer(&app.home, &peer)?;
                println!("peer revoked: {}", peer.id);
                Ok(())
            }
            TrustCommands::Request { peer_id } => extended::cmd_trust_request(&app, &peer_id),
            TrustCommands::Graph => extended::cmd_trust_graph(&app),
            TrustCommands::Requests => extended::cmd_trust_requests(&app),
            TrustCommands::Delegate {
                target,
                r#type,
                scope,
            } => extended::cmd_trust_delegate(&app, &target, &r#type, &scope),
            TrustCommands::RevokeDelegation { id } => {
                extended::cmd_trust_revoke_delegation(&app, &id)
            }
            TrustCommands::InspectDelegation { chain, root } => {
                extended::cmd_trust_inspect_delegation(&app, chain, root)
            }
            #[cfg(feature = "runtime")]
            TrustCommands::Recommend => runtime_handlers::cmd_trust_recommend(&app),
            #[cfg(feature = "runtime")]
            TrustCommands::Explain { decision } => {
                runtime_handlers::cmd_trust_explain(&app, decision)
            }
            TrustCommands::Export { dest } => extended::cmd_trust_export(&app, dest),
            TrustCommands::Validate { source } => extended::cmd_trust_validate(&app, source),
        },
        Commands::Export { repo, output } => {
            let repo = app.find_repo(repo.as_deref())?;
            let result = export_bundle(
                &app,
                &repo,
                ExportOptions {
                    output,
                    ..Default::default()
                },
            )?;
            println!("bundle exported: {}", result.bundle.display());
            Ok(())
        }
        Commands::Import { bundle, vault } => {
            let (vault, repo) = import_bundle(&app, &bundle, vault.as_deref())?;
            println!("bundle imported into vault {}", vault.name);
            println!("  repo: {} ({})", repo.name, repo.id);
            println!("  sync_state: {}", repo.sync_state);
            Ok(())
        }
        Commands::Bundle { command } => match command {
            BundleCommands::Create {
                repo,
                output,
                structured,
                encrypt,
                since,
            } => extended::cmd_bundle_create(&app, repo, output, structured, encrypt, since),
            BundleCommands::Import { bundle, vault } => {
                let (vault, repo) = import_bundle(&app, &bundle, vault.as_deref())?;
                println!("bundle imported: {} in vault {}", repo.name, vault.name);
                Ok(())
            }
            BundleCommands::Validate { bundle } => extended::cmd_bundle_validate(&bundle),
        },
        Commands::Lineage { command } => match command {
            LineageCommands::Inspect { checkpoint_id } => {
                extended::cmd_lineage_inspect(&app, &checkpoint_id)
            }
            LineageCommands::Hash { checkpoint_id } => {
                extended::cmd_lineage_hash(&app, &checkpoint_id)
            }
            LineageCommands::Verify { checkpoint_id, hash } => {
                extended::cmd_lineage_verify(&app, &checkpoint_id, &hash)
            }
        },
        Commands::Manifest { command } => match command {
            ManifestCommands::Inspect { path } => extended::cmd_manifest_inspect(&path),
            ManifestCommands::Verify { path } => extended::cmd_manifest_verify_file(&path),
        },
        Commands::Cas { command } => match command {
            CasCommands::Store { path } => extended::cmd_cas_store(&app, path),
            CasCommands::Load { chunk_id, output } => {
                extended::cmd_cas_load(&app, &chunk_id, output)
            }
            CasCommands::Verify { chunk_id } => extended::cmd_cas_verify(&app, &chunk_id),
        },
        Commands::Merkle { command } => match command {
            MerkleCommands::Verify { leaves } => extended::cmd_merkle_verify(&leaves),
        },
        #[cfg(feature = "federation")]
        Commands::Mesh { command } => match command {
            MeshCommands::Reconcile { repo } => extended::cmd_multi_hop_reconcile(&app, &repo),
        },
        #[cfg(feature = "federation")]
        Commands::Route { command } => match command {
            RouteCommands::Inspect { destination, global } => {
                extended::cmd_route_inspect_global(&app, destination, global)
            }
            RouteCommands::Verify { route_id } => extended::cmd_route_verify(&app, &route_id),
        },
        #[cfg(feature = "federation")]
        Commands::Relay { command } => match command {
            RelayCommands::Enable => {
                gitp2p_federation::set_relay_enabled(&app, true)?;
                println!("relay enabled");
                Ok(())
            }
            RelayCommands::Disable => {
                gitp2p_federation::set_relay_enabled(&app, false)?;
                println!("relay disabled");
                Ok(())
            }
            RelayCommands::Status => extended::cmd_relay_status(&app),
        },
        #[cfg(feature = "federation")]
        Commands::Topology { command } => match command {
            TopologyCommands::Peers => extended::cmd_topology(&app, "peers"),
            TopologyCommands::Trust => extended::cmd_topology(&app, "trust"),
            TopologyCommands::Routes => extended::cmd_topology(&app, "routes"),
            TopologyCommands::Vaults => extended::cmd_topology(&app, "vaults"),
            TopologyCommands::Summary => extended::cmd_topology(&app, "summary"),
        },
        Commands::Id { command } => match command {
            IdCommands::Create => extended::cmd_id_create(&app),
            IdCommands::Inspect => extended::cmd_id_inspect(&app),
            IdCommands::Export { dest } => extended::cmd_id_export(&app, dest),
            IdCommands::Import { source } => extended::cmd_id_import(&app, source),
        },
        Commands::Media { command } => match command {
            MediaCommands::Export { source, media } => extended::cmd_media_export(source, media),
            MediaCommands::Import { media, name } => extended::cmd_media_import(media, name),
        },
        #[cfg(feature = "federation")]
        Commands::Domain { command } => match command {
            DomainCommands::Create { name } => extended::cmd_domain_create(&app, &name),
            DomainCommands::Inspect { domain_id } => extended::cmd_domain_inspect(&app, domain_id),
            DomainCommands::Policy { command } => match command {
                DomainPolicyCommands::Set {
                    domain_id,
                    field,
                    value,
                } => extended::cmd_domain_policy_set(&app, &domain_id, &field, &value),
            },
            DomainCommands::Delete { domain_id, yes } => {
                extended::cmd_domain_delete(&app, &domain_id, yes)
            }
            DomainCommands::Migrate { to, vault } => extended::cmd_domain_migrate(&app, &to, vault),
        },
        #[cfg(feature = "federation")]
        Commands::Gateway { command } => match command {
            GatewayCommands::Create { domain, listen } => {
                extended::cmd_gateway_create(&app, domain, listen)
            }
            GatewayCommands::Inspect { gateway_id } => {
                extended::cmd_gateway_inspect(&app, gateway_id)
            }
        },
        #[cfg(feature = "federation")]
        Commands::PeerDomain { command } => match command {
            PeerDomainCommands::Connect {
                remote_domain,
                gateway,
            } => extended::cmd_peer_domain_connect(&app, &remote_domain, gateway),
            PeerDomainCommands::Revoke { remote_domain } => {
                extended::cmd_peer_domain_revoke(&app, &remote_domain)
            }
            PeerDomainCommands::Inspect { remote_domain } => {
                extended::cmd_peer_domain_inspect(&app, remote_domain)
            }
        },
        #[cfg(feature = "federation")]
        Commands::Discover { command } => match command {
            DiscoverCommands::Domains => extended::cmd_discover("domains", &app, None),
            DiscoverCommands::Gateways => extended::cmd_discover("gateways", &app, None),
            DiscoverCommands::Vaults => extended::cmd_discover("vaults", &app, None),
            DiscoverCommands::Replicas { repo } => extended::cmd_discover("replicas", &app, repo),
        },
        Commands::Verify { command } => match command {
            #[cfg(feature = "federation")]
            VerifyCommands::Domain { id } => extended::cmd_verify_v5(&app, "domain", &id),
            #[cfg(feature = "federation")]
            VerifyCommands::Gateway { id } => extended::cmd_verify_v5(&app, "gateway", &id),
            #[cfg(feature = "federation")]
            VerifyCommands::Peering { remote_domain } => {
                extended::cmd_verify_v5(&app, "peering", &remote_domain)
            }
            VerifyCommands::Delegation { id } => extended::cmd_verify_v5(&app, "delegation", &id),
            #[cfg(feature = "federation")]
            VerifyCommands::Route { route_id } => extended::cmd_verify_v5(&app, "route", &route_id),
            #[cfg(feature = "runtime")]
            VerifyCommands::Policy { id } => extended::cmd_verify_policy(&app, &id),
        },
        #[cfg(feature = "runtime")]
        Commands::Policy { command } => match command {
            RuntimePolicyCommands::Create {
                name,
                kind,
                vault,
                fields,
            } => runtime_handlers::cmd_runtime_policy_create(&app, &name, &kind, &vault, &fields),
            RuntimePolicyCommands::Inspect { reference } => {
                runtime_handlers::cmd_runtime_policy_inspect(&app, reference)
            }
            RuntimePolicyCommands::Update {
                reference,
                fields,
                active,
            } => runtime_handlers::cmd_runtime_policy_update(&app, &reference, fields, active),
            RuntimePolicyCommands::Delete { reference } => {
                runtime_handlers::cmd_runtime_policy_delete(&app, &reference)
            }
            RuntimePolicyCommands::History { org } => {
                runtime_handlers::cmd_policy_history(&app, org)
            }
        },
        #[cfg(feature = "runtime")]
        Commands::Health { command } => match command {
            HealthCommands::Inspect { vault } => runtime_handlers::cmd_health_inspect(&app, &vault),
        },
        #[cfg(feature = "runtime")]
        Commands::Automation { command } => match command {
            AutomationCommands::Run { vault, dry_run, org } => {
                if let Some(org) = org {
                    runtime_handlers::cmd_automation_run_gated(&app, &org, &vault, dry_run)
                } else {
                    runtime_handlers::cmd_automation_run(&app, &vault, dry_run)
                }
            }
            AutomationCommands::Pause => runtime_handlers::cmd_automation_pause(&app),
            AutomationCommands::Resume => runtime_handlers::cmd_automation_resume(&app),
        },
        #[cfg(feature = "runtime")]
        Commands::Explain { command } => match command {
            ExplainCommands::Decision { id } => runtime_handlers::cmd_explain_decision(&app, id),
        },
        #[cfg(feature = "runtime")]
        Commands::Replica { command } => match command {
            ReplicaCommands::Explain { decision } => {
                runtime_handlers::cmd_replica_explain(&app, decision)
            }
        },
        #[cfg(feature = "runtime")]
        Commands::Recovery { command } => match command {
            RecoveryCommands::Plan { vault } => runtime_handlers::cmd_recovery_plan(&app, &vault),
        },
        #[cfg(feature = "runtime")]
        Commands::Replay { command } => match command {
            ReplayCommands::Decision { id, dry_run } => {
                runtime_handlers::cmd_replay_decision(&app, &id, dry_run)
            }
        },
        #[cfg(feature = "enterprise")]
        Commands::Org { command } => match command {
            OrgCommands::Create { name } => runtime_handlers::cmd_org_create(&app, &name),
            OrgCommands::Inspect { reference } => runtime_handlers::cmd_org_inspect(&app, reference),
            OrgCommands::Update { reference, name } => {
                runtime_handlers::cmd_org_update(&app, &reference, name)
            }
            OrgCommands::Member { command } => match command {
                OrgMemberCommands::Add { org, peer_id } => {
                    runtime_handlers::cmd_org_member_add(&app, &org, &peer_id)
                }
                OrgMemberCommands::Remove { org, peer_id } => {
                    runtime_handlers::cmd_org_member_remove(&app, &org, &peer_id)
                }
            },
            OrgCommands::Trust { command } => match command {
                OrgTrustCommands::Establish { org, remote_org } => {
                    runtime_handlers::cmd_org_trust_establish(&app, &org, &remote_org)
                }
                OrgTrustCommands::Inspect { org, remote } => {
                    runtime_handlers::cmd_org_trust_inspect(&app, &org, remote)
                }
                OrgTrustCommands::Revoke { org, remote_org } => {
                    runtime_handlers::cmd_org_trust_revoke(&app, &org, &remote_org)
                }
            },
        },
        #[cfg(feature = "enterprise")]
        Commands::Team { command } => match command {
            TeamCommands::Create { org, name } => runtime_handlers::cmd_team_create(&app, &org, &name),
            TeamCommands::Inspect { reference, org } => {
                runtime_handlers::cmd_team_inspect(&app, reference, org)
            }
            TeamCommands::Member { team, peer_id } => {
                runtime_handlers::cmd_team_member_add(&app, &team, &peer_id)
            }
        },
        #[cfg(feature = "enterprise")]
        Commands::Role { command } => match command {
            RoleCommands::Assign { org, peer_id, role } => {
                runtime_handlers::cmd_role_assign(&app, &org, &peer_id, &role)
            }
            RoleCommands::Revoke { org, peer_id } => {
                runtime_handlers::cmd_role_revoke(&app, &org, &peer_id)
            }
            RoleCommands::Inspect { org } => runtime_handlers::cmd_role_inspect(&app, &org),
        },
        #[cfg(feature = "enterprise")]
        Commands::Governance { command } => match command {
            GovernanceCommands::Propose {
                org,
                r#type,
                subject_id,
                details,
            } => runtime_handlers::cmd_governance_propose(&app, &org, &r#type, &subject_id, &details),
            GovernanceCommands::Review { id } => runtime_handlers::cmd_governance_review(&app, &id),
            GovernanceCommands::Approve { org, id } => {
                runtime_handlers::cmd_governance_approve(&app, &org, &id)
            }
            GovernanceCommands::Reject { id } => runtime_handlers::cmd_governance_reject(&app, &id),
            GovernanceCommands::Inspect { org } => runtime_handlers::cmd_governance_inspect(&app, &org),
        },
        #[cfg(feature = "enterprise")]
        Commands::Audit { command } => match command {
            AuditCommands::Search { org, source, action } => {
                runtime_handlers::cmd_audit_search(&app, org, source, action)
            }
            AuditCommands::Export { org } => runtime_handlers::cmd_audit_export(&app, org),
        },
        #[cfg(feature = "enterprise")]
        Commands::Compliance { command } => match command {
            ComplianceCommands::Inspect { org } => {
                runtime_handlers::cmd_compliance_inspect(&app, &org)
            }
            ComplianceCommands::Report { org } => runtime_handlers::cmd_compliance_report(&app, &org),
        },
        #[cfg(feature = "enterprise")]
        Commands::Admin { command } => match command {
            AdminCommands::Delegate { org, delegate, scope } => {
                runtime_handlers::cmd_admin_delegate(&app, &org, &delegate, &scope)
            }
            AdminCommands::Revoke { org, delegate } => {
                runtime_handlers::cmd_admin_revoke(&app, &org, &delegate)
            }
            AdminCommands::Inspect { org } => runtime_handlers::cmd_admin_inspect(&app, &org),
        },
        #[cfg(feature = "enterprise")]
        Commands::Visibility { command } => match command {
            VisibilityCommands::Report { org } => runtime_handlers::cmd_visibility_report(&app, &org),
        },
        Commands::Reconcile { command } => match command {
            ReconcileCommands::Run { repo } => extended::cmd_reconcile(&app, &repo),
            ReconcileCommands::History { repo } => extended::cmd_reconcile_history(&app, repo),
        },
        Commands::Sign { payload, checkpoint } => extended::cmd_sign(&app, payload, checkpoint),
        Commands::Signature { command } => match command {
            SignatureCommands::Verify {
                signature,
                payload,
                public_key,
                checkpoint,
            } => extended::cmd_signature_verify(payload, &signature, public_key, checkpoint, &app),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_version_matches_crate() {
        assert!(!VERSION.is_empty());
    }
}
