use gitp2p_core::{Result};
use gitp2p_core::util::{create_dir_all, timestamp};
use gitp2p_core::App;

#[derive(Clone, Debug)]
pub struct RelayState {
    pub enabled: bool,
    pub forwarded: u64,
}

pub fn relay_status(app: &App) -> Result<RelayState> {
    let path = app.home.join("relay").join("state");
    if !path.exists() {
        return Ok(RelayState {
            enabled: false,
            forwarded: 0,
        });
    }
    let map = gitp2p_core::read_kv(&path)?;
    Ok(RelayState {
        enabled: gitp2p_core::optional_field(&map, "enabled") == "true",
        forwarded: gitp2p_core::optional_field(&map, "forwarded")
            .parse()
            .unwrap_or(0),
    })
}

pub fn set_relay_enabled(app: &App, enabled: bool) -> Result<()> {
    create_dir_all(app.home.join("relay"))?;
    gitp2p_core::write_kv(
        &app.home.join("relay").join("state"),
        &[
            ("enabled", if enabled { "true" } else { "false" }),
            ("updated_at", &timestamp()),
            (
                "forwarded",
                &relay_status(app)?.forwarded.to_string(),
            ),
        ],
    )
}

pub fn forward_propagation(app: &App, artifact: &str, next_hop: &str) -> Result<()> {
    let state = relay_status(app)?;
    if !state.enabled {
        return Err(gitp2p_core::AppError::new("relay is disabled"));
    }
    let cache = app.home.join("relay").join("cache");
    create_dir_all(&cache)?;
    gitp2p_core::write_kv(
        &cache.join(format!("fwd-{}", timestamp())),
        &[
            ("artifact", artifact),
            ("next_hop", next_hop),
            ("forwarded_at", &timestamp()),
        ],
    )?;
    gitp2p_core::write_kv(
        &app.home.join("relay").join("state"),
        &[
            ("enabled", "true"),
            ("forwarded", &(state.forwarded + 1).to_string()),
            ("updated_at", &timestamp()),
        ],
    )
}
