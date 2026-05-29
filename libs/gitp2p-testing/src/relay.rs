use gitp2p_federation::{failover_route, set_relay_enabled};
use gitp2p_core::App;

pub fn simulate_relay_loss(app: &App, route_id: &str) -> gitp2p_core::Result<()> {
    set_relay_enabled(app, true)?;
    set_relay_enabled(app, false)?;
    let _ = failover_route(app, route_id)?;
    Ok(())
}
