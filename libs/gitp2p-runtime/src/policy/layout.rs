use std::path::{Path, PathBuf};

use gitp2p_core::util::create_dir_all;

pub fn runtime_root(home: &Path) -> PathBuf {
    home.join("runtime")
}

pub fn policies_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("policies")
}

pub fn decisions_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("decisions")
}

pub fn plans_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("plans")
}

pub fn health_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("health")
}

pub fn explanations_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("explanations")
}

pub fn automation_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("automation")
}

pub fn agents_dir(home: &Path) -> PathBuf {
    runtime_root(home).join("agents")
}

pub fn automation_state_path(home: &Path) -> PathBuf {
    automation_dir(home).join("state")
}

pub fn ensure_runtime_layout(home: &Path) -> gitp2p_core::Result<()> {
    for dir in [
        policies_dir(home),
        decisions_dir(home),
        plans_dir(home),
        health_dir(home),
        explanations_dir(home),
        automation_dir(home),
        agents_dir(home),
    ] {
        create_dir_all(dir)?;
    }
    Ok(())
}
