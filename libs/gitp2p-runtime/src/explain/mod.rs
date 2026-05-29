use gitp2p_core::identity::explanation_id;
use gitp2p_core::{Explanation, Result, RuntimeDecision};
use crate::policy::{ensure_runtime_layout, explanations_dir, find_policy};
use gitp2p_core::App;

pub fn build_explanation(app: &App, decision: &RuntimeDecision) -> Result<Explanation> {
    let policy_source = if decision.policy_id.is_empty() {
        "none".into()
    } else {
        find_policy(app, &decision.policy_id)
            .map(|p| format!("{} ({})", p.name, p.id))
            .unwrap_or_else(|_| decision.policy_id.clone())
    };

    Ok(Explanation {
        id: explanation_id(&decision.id),
        decision_id: decision.id.clone(),
        why: format!("Policy or federation state triggered {} agent", decision.agent),
        what: decision.action.clone(),
        when_at: decision.created_at.clone(),
        policy_source,
        expected_outcome: decision.expected_outcome.clone(),
        created_at: gitp2p_core::util::timestamp(),
    })
}

pub fn record_explanation(app: &App, decision: &RuntimeDecision) -> Result<Explanation> {
    ensure_runtime_layout(&app.home)?;
    let explanation = build_explanation(app, decision)?;
    gitp2p_core::write_kv(
        &explanations_dir(&app.home).join(&explanation.id),
        &[
            ("id", &explanation.id),
            ("decision_id", &explanation.decision_id),
            ("why", &explanation.why),
            ("what", &explanation.what),
            ("when_at", &explanation.when_at),
            ("policy_source", &explanation.policy_source),
            ("expected_outcome", &explanation.expected_outcome),
            ("created_at", &explanation.created_at),
        ],
    )?;
    Ok(explanation)
}

pub fn find_explanation(app: &App, decision_id: &str) -> Result<Explanation> {
    ensure_runtime_layout(&app.home)?;
    let dir = explanations_dir(&app.home);
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = gitp2p_core::read_kv(&entry.path())?;
            if gitp2p_core::optional_field(&map, "decision_id") == decision_id {
                return Ok(Explanation {
                    id: gitp2p_core::field(&map, "id")?,
                    decision_id: gitp2p_core::field(&map, "decision_id")?,
                    why: gitp2p_core::field(&map, "why")?,
                    what: gitp2p_core::field(&map, "what")?,
                    when_at: gitp2p_core::field(&map, "when_at")?,
                    policy_source: gitp2p_core::optional_field(&map, "policy_source"),
                    expected_outcome: gitp2p_core::optional_field(&map, "expected_outcome"),
                    created_at: gitp2p_core::field(&map, "created_at")?,
                });
            }
        }
    }
    Err(gitp2p_core::AppError::new(format!(
        "explanation for decision '{decision_id}' not found"
    )))
}

pub fn inspect_history(app: &App) -> Result<Vec<Explanation>> {
    ensure_runtime_layout(&app.home)?;
    let dir = explanations_dir(&app.home);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut history = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            let map = gitp2p_core::read_kv(&entry.path())?;
            history.push(Explanation {
                id: gitp2p_core::field(&map, "id")?,
                decision_id: gitp2p_core::field(&map, "decision_id")?,
                why: gitp2p_core::field(&map, "why")?,
                what: gitp2p_core::field(&map, "what")?,
                when_at: gitp2p_core::field(&map, "when_at")?,
                policy_source: gitp2p_core::optional_field(&map, "policy_source"),
                expected_outcome: gitp2p_core::optional_field(&map, "expected_outcome"),
                created_at: gitp2p_core::field(&map, "created_at")?,
            });
        }
    }
    history.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(history)
}

pub fn format_explanation(explanation: &Explanation) -> String {
    format!(
        "Action: {}\nWhy: {}\nWhen: {}\nPolicy: {}\nExpected Outcome: {}",
        explanation.what,
        explanation.why,
        explanation.when_at,
        explanation.policy_source,
        explanation.expected_outcome
    )
}
