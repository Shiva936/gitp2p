use gitp2p_core::identity::runtime_decision_id;
use gitp2p_core::{Result, RuntimeDecision, RuntimePlan, RuntimePolicy, TrustRecommendation};
use crate::policy::{ensure_runtime_layout, agents_dir};
use gitp2p_core::App;

pub fn plan_trust(
    app: &App,
    vault: &str,
    policies: &[RuntimePolicy],
) -> Result<Option<(RuntimeDecision, RuntimePlan)>> {
    let _trust_policies: Vec<_> = policies.iter().filter(|p| p.kind == "trust").collect();
    let peers = app.all_peers()?;
    let untrusted: Vec<_> = peers
        .into_iter()
        .filter(|p| p.trust_state != "trusted" && p.trust_state != "revoked")
        .collect();
    if untrusted.is_empty() {
        return Ok(None);
    }

    let peer = &untrusted[0];
    let decision_id = runtime_decision_id("trust");

    let decision = RuntimeDecision {
        id: decision_id.clone(),
        agent: "trust".into(),
        phase: "recommend".into(),
        policy_id: String::new(),
        action: format!("recommend_trust:{}", peer.id),
        expected_outcome: format!("Advisory: consider trusting peer {}", peer.id),
        status: "recommended".into(),
        vault_id: vault.into(),
        repo_id: String::new(),
        details: format!("peer_trust_state={}", peer.trust_state),
        created_at: gitp2p_core::util::timestamp(),
        signature: String::new(),
        signed_by: String::new(),
        signed_at: String::new(),
    };

    let rec = TrustRecommendation {
        id: format!("trec-{}", &decision_id[decision_id.len().saturating_sub(12)..]),
        peer_id: peer.id.clone(),
        recommendation: "approve".into(),
        reason: "Peer discovered but not trusted; sync requires trust".into(),
        decision_id: decision_id.clone(),
        created_at: gitp2p_core::util::timestamp(),
    };
    save_recommendation(app, &rec)?;

    // Trust agent is advisory only - no execution plan
    Ok(Some((decision, RuntimePlan {
        id: format!("plan-trust-{}", &decision_id[decision_id.len().saturating_sub(8)..]),
        kind: "trust".into(),
        decision_id,
        vault_id: vault.into(),
        repo_id: String::new(),
        target_peer: peer.id.clone(),
        action: "recommend".into(),
        status: "advisory".into(),
        created_at: gitp2p_core::util::timestamp(),
    })))
}

fn save_recommendation(app: &App, rec: &TrustRecommendation) -> Result<()> {
    ensure_runtime_layout(&app.home)?;
    gitp2p_core::write_kv(
        &agents_dir(&app.home).join("trust").join(&rec.id),
        &[
            ("id", &rec.id),
            ("peer_id", &rec.peer_id),
            ("recommendation", &rec.recommendation),
            ("reason", &rec.reason),
            ("decision_id", &rec.decision_id),
            ("created_at", &rec.created_at),
        ],
    )
}

pub fn list_recommendations(app: &App) -> Result<Vec<TrustRecommendation>> {
    ensure_runtime_layout(&app.home)?;
    let dir = agents_dir(&app.home).join("trust");
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut recs = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = gitp2p_core::read_kv(&entry.path())?;
            recs.push(TrustRecommendation {
                id: gitp2p_core::field(&map, "id")?,
                peer_id: gitp2p_core::field(&map, "peer_id")?,
                recommendation: gitp2p_core::field(&map, "recommendation")?,
                reason: gitp2p_core::field(&map, "reason")?,
                decision_id: gitp2p_core::optional_field(&map, "decision_id"),
                created_at: gitp2p_core::field(&map, "created_at")?,
            });
        }
    }
    Ok(recs)
}
