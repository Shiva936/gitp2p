use gitp2p_core::identity::runtime_decision_id;
use gitp2p_core::{Result, RuntimeDecision, RuntimePolicy};
use gitp2p_core::App;

pub fn plan_optimization(
    app: &App,
    vault: &str,
    _policies: &[RuntimePolicy],
) -> Result<Option<RuntimeDecision>> {
    let peers: Vec<_> = app
        .all_peers()?
        .into_iter()
        .filter(|p| p.trust_state == "trusted")
        .collect();
    if peers.len() < 2 {
        return Ok(None);
    }

    let vault_obj = app.find_vault(vault)?;
    let replication_dir = vault_obj.path.join("replication");
    let mut peer_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    if replication_dir.exists() {
        for entry in std::fs::read_dir(replication_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name().into_string().unwrap_or_default();
                if name.starts_with("recon-") {
                    continue;
                }
                let map = gitp2p_core::read_kv(&entry.path())?;
                let peer_id = gitp2p_core::optional_field(&map, "peer_id");
                if !peer_id.is_empty() {
                    *peer_counts.entry(peer_id).or_default() += 1;
                }
            }
        }
    }

    let used_peers = peer_counts.len();
    if used_peers >= peers.len() {
        return Ok(None);
    }

    let decision_id = runtime_decision_id("optimization");
    Ok(Some(RuntimeDecision {
        id: decision_id,
        agent: "optimization".into(),
        phase: "recommend".into(),
        policy_id: String::new(),
        action: "rebalance_topology".into(),
        expected_outcome: format!(
            "Spread replicas across {} trusted peers (currently using {})",
            peers.len(),
            used_peers
        ),
        status: "planned".into(),
        vault_id: vault.into(),
        repo_id: String::new(),
        details: format!(
            "trusted_peers={},replica_peers={used_peers}",
            peers.len()
        ),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    }))
}
