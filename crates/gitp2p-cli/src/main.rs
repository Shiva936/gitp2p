mod extended;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use gitp2p_bundle::{export_bundle, import_bundle, ExportOptions};
use gitp2p_metadata::{RepoAction, VERSION};
use gitp2p_metadata::util::{count_files, empty_dash, split_csv};
use gitp2p_recovery::{
    best_checkpoint_peers, doctor_repo, recover_from_best_peer, recover_from_peer, recover_local,
};
use gitp2p_sync::{
    discover_filesystem, discover_lan, advertise_lan, list_inflight_sessions, sync_local,
    sync_to_peer,
};
use gitp2p_trust::{set_policy_field, show_policy, write_peer};
use gitp2p_trust::peer::read_peer;
use gitp2p_vault::{
    checkpoints_for_repo, checkpoints_for_vault, create_checkpoint, create_vault, delete_vault,
    prune_checkpoints, add_repo, remove_repo, App,
};
use gitp2p_vault::app::read_checkpoint;
use gitp2p_trust::merged_policy;

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
    Route {
        #[command(subcommand)]
        command: RouteCommands,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommands,
    },
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
    Domain {
        #[command(subcommand)]
        command: DomainCommands,
    },
    Gateway {
        #[command(subcommand)]
        command: GatewayCommands,
    },
    PeerDomain {
        #[command(subcommand)]
        command: PeerDomainCommands,
    },
    Discover {
        #[command(subcommand)]
        command: DiscoverCommands,
    },
    Verify {
        #[command(subcommand)]
        command: VerifyCommands,
    },
}

#[derive(Subcommand)]
enum IdentityCommands {
    Show,
    Inspect,
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
}

#[derive(Subcommand)]
enum SyncSubcommands {
    Status { repo: Option<String> },
    Inspect { session_id: Option<String> },
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
    Info { peer_id: String },
    Verify { peer_id: String },
    Listen,
}

#[derive(Subcommand)]
enum TrustCommands {
    Approve {
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
    Global {
        repo: String,
        #[arg(long)]
        domain: Option<String>,
        #[arg(long)]
        target: Option<PathBuf>,
    },
    Sources { repo: String },
}

#[derive(Subcommand)]
enum VerifyCommands {
    Domain { id: String },
    Gateway { id: String },
    Peering { remote_domain: String },
    Delegation { id: String },
    Route { route_id: String },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> gitp2p_metadata::Result<()> {
    let cli = Cli::parse();
    let app = App::load()?;
    app.ensure_home()?;
    app.ensure_identity()?;

    match cli.command {
        Commands::Identity { command } => match command {
            IdentityCommands::Show | IdentityCommands::Inspect => {
                let identity = app.ensure_identity()?;
                println!("peer_id: {}", identity.peer_id);
                println!("fingerprint: {}", identity.fingerprint);
                println!("public_key: {}", identity.public_key);
                Ok(())
            }
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
                    Err(gitp2p_metadata::AppError::new("repository needs recovery"))
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
                            let map = gitp2p_metadata::read_kv(&entry.path())?;
                            println!(
                                "{}\t{}\t{}\t{}\t{}\t{}",
                                gitp2p_metadata::optional_field(&map, "peer_id"),
                                gitp2p_metadata::optional_field(&map, "repo_id"),
                                gitp2p_metadata::optional_field(&map, "checkpoint_id"),
                                gitp2p_metadata::optional_field(&map, "state"),
                                gitp2p_metadata::optional_field(&map, "checkpoint_lineage"),
                                gitp2p_metadata::optional_field(&map, "propagation_state"),
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
        },
        Commands::Recover {
            repo,
            peer,
            checkpoint,
            target,
            auto_recover,
            offline,
            network,
            command,
        } => {
            if let Some(RecoverCommands::Global {
                repo,
                domain,
                target,
            }) = command
            {
                return extended::cmd_recover_global(&app, &repo, domain, target);
            }
            if let Some(RecoverCommands::Sources { repo }) = command {
                return extended::cmd_recover_sources(&app, &repo);
            }
            if let Some(bundle) = offline {
                return extended::cmd_recover_offline(&app, bundle, None);
            }
            if let Some(dest) = network {
                return extended::cmd_recover_network(&app, &repo, &dest);
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
            domain,
            requires_approval,
            enforce_retention,
            command,
            trailing,
        } => {
            if let Some(SyncSubcommands::Inspect { session_id }) = command {
                return extended::cmd_sync_inspect(&app, session_id);
            }
            if let Some(SyncSubcommands::Status { repo }) = command {
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
            if let Some(domain_id) = domain {
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
            PeersCommands::Info { peer_id } => {
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
            TrustCommands::Approve { peer_id, role } => {
                let mut peer = app.find_peer(&peer_id)?;
                peer.trust_state = role.unwrap_or_else(|| "trusted".to_string());
                write_peer(&app.home, &peer)?;
                println!("peer approved: {}", peer.id);
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
            LineageCommands::Verify { checkpoint_id, hash } => {
                extended::cmd_lineage_verify(&app, &checkpoint_id, &hash)
            }
        },
        Commands::Manifest { command } => match command {
            ManifestCommands::Inspect { path } => extended::cmd_manifest_inspect(&path),
            ManifestCommands::Verify { path } => extended::cmd_manifest_verify(&path),
        },
        Commands::Route { command } => match command {
            RouteCommands::Inspect { destination, global } => {
                extended::cmd_route_inspect_global(&app, destination, global)
            }
            RouteCommands::Verify { route_id } => extended::cmd_route_verify(&app, &route_id),
        },
        Commands::Relay { command } => match command {
            RelayCommands::Enable => {
                gitp2p_relay::set_relay_enabled(&app, true)?;
                println!("relay enabled");
                Ok(())
            }
            RelayCommands::Disable => {
                gitp2p_relay::set_relay_enabled(&app, false)?;
                println!("relay disabled");
                Ok(())
            }
            RelayCommands::Status => extended::cmd_relay_status(&app),
        },
        Commands::Topology { command } => match command {
            TopologyCommands::Peers => extended::cmd_topology(&app, "peers"),
            TopologyCommands::Trust => extended::cmd_topology(&app, "trust"),
            TopologyCommands::Routes => extended::cmd_topology(&app, "routes"),
            TopologyCommands::Vaults => extended::cmd_topology(&app, "vaults"),
            TopologyCommands::Summary => extended::cmd_topology(&app, "summary"),
        },
        Commands::Id { command } => match command {
            IdCommands::Inspect => extended::cmd_id_inspect(&app),
            IdCommands::Export { dest } => extended::cmd_id_export(&app, dest),
            IdCommands::Import { source } => extended::cmd_id_import(&app, source),
        },
        Commands::Media { command } => match command {
            MediaCommands::Export { source, media } => extended::cmd_media_export(source, media),
            MediaCommands::Import { media, name } => extended::cmd_media_import(media, name),
        },
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
        Commands::Gateway { command } => match command {
            GatewayCommands::Create { domain, listen } => {
                extended::cmd_gateway_create(&app, domain, listen)
            }
            GatewayCommands::Inspect { gateway_id } => {
                extended::cmd_gateway_inspect(&app, gateway_id)
            }
        },
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
        Commands::Discover { command } => match command {
            DiscoverCommands::Domains => extended::cmd_discover("domains", &app, None),
            DiscoverCommands::Gateways => extended::cmd_discover("gateways", &app, None),
            DiscoverCommands::Vaults => extended::cmd_discover("vaults", &app, None),
            DiscoverCommands::Replicas { repo } => extended::cmd_discover("replicas", &app, repo),
        },
        Commands::Verify { command } => match command {
            VerifyCommands::Domain { id } => extended::cmd_verify_v5(&app, "domain", &id),
            VerifyCommands::Gateway { id } => extended::cmd_verify_v5(&app, "gateway", &id),
            VerifyCommands::Peering { remote_domain } => {
                extended::cmd_verify_v5(&app, "peering", &remote_domain)
            }
            VerifyCommands::Delegation { id } => extended::cmd_verify_v5(&app, "delegation", &id),
            VerifyCommands::Route { route_id } => extended::cmd_verify_v5(&app, "route", &route_id),
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
