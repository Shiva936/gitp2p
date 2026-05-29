use crate::layout::*;

use gitp2p_core::{AutomationState, HealthReport, Result, RuntimeDecision};
use gitp2p_core::App;

#[derive(Clone, Debug)]
pub struct RuntimeTickReport {
    pub decisions: Vec<RuntimeDecision>,
    pub health: Option<HealthReport>,
    pub paused: bool,
    pub dry_run: bool,
}

pub fn load_automation_state(app: &App) -> Result<AutomationState> {
    ensure_runtime_layout(&app.home)?;
    let path = automation_state_path(&app.home);
    if !path.exists() {
        return Ok(AutomationState::default());
    }
    let map = gitp2p_core::read_kv(&path)?;
    Ok(AutomationState {
        paused: gitp2p_core::optional_field(&map, "paused"),
        last_tick: gitp2p_core::optional_field(&map, "last_tick"),
    })
}

pub fn save_automation_state(app: &App, state: &AutomationState) -> Result<()> {
    ensure_runtime_layout(&app.home)?;
    gitp2p_core::write_kv(
        &automation_state_path(&app.home),
        &[
            ("paused", &state.paused),
            ("last_tick", &state.last_tick),
        ],
    )
}

pub fn automation_pause(app: &App) -> Result<()> {
    let mut state = load_automation_state(app)?;
    state.paused = "true".into();
    save_automation_state(app, &state)
}

pub fn automation_resume(app: &App) -> Result<()> {
    let mut state = load_automation_state(app)?;
    state.paused = "false".into();
    save_automation_state(app, &state)
}

pub fn automation_tick(app: &App, vault: &str, dry_run: bool) -> Result<RuntimeTickReport> {
    ensure_runtime_layout(&app.home)?;
    let state = load_automation_state(app)?;
    if state.paused == "true" {
        return Ok(RuntimeTickReport {
            decisions: Vec::new(),
            health: None,
            paused: true,
            dry_run,
        });
    }

    let decisions = crate::run_tick(app, vault, dry_run)?;
    let health = crate::calculate_health(app, vault).ok();

    let mut new_state = state;
    new_state.last_tick = gitp2p_core::util::timestamp();
    save_automation_state(app, &new_state)?;

    Ok(RuntimeTickReport {
        decisions,
        health,
        paused: false,
        dry_run,
    })
}
