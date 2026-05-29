use std::path::{Path, PathBuf};

use gitp2p_core::util::create_dir_all;

pub fn enterprise_root(home: &Path) -> PathBuf {
    home.join("enterprise")
}

pub fn organizations_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("organizations")
}

pub fn teams_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("teams")
}

pub fn roles_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("roles")
}

pub fn governance_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("governance")
}

pub fn audit_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("audit")
}

pub fn compliance_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("compliance")
}

pub fn administration_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("administration")
}

pub fn org_trust_dir(home: &Path) -> PathBuf {
    enterprise_root(home).join("org-trust")
}

pub fn ensure_enterprise_layout(home: &Path) -> gitp2p_core::Result<()> {
    for dir in [
        organizations_dir(home),
        teams_dir(home),
        roles_dir(home),
        governance_dir(home),
        audit_dir(home),
        compliance_dir(home),
        administration_dir(home),
        org_trust_dir(home),
    ] {
        create_dir_all(dir)?;
    }
    Ok(())
}
