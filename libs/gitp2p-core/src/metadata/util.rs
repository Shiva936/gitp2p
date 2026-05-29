use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Result;
use crate::Vault;

pub fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn default_home() -> Result<PathBuf> {
    if let Some(home) = env::var_os("GITP2P_HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Some(home) = env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".gitp2p"));
    }
    if let Some(profile) = env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(profile).join(".gitp2p"));
    }
    Ok(env::current_dir()?.join(".gitp2p"))
}

pub fn listen_port() -> u16 {
    env::var("GITP2P_LISTEN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9134)
}

pub fn transport_mode() -> String {
    env::var("GITP2P_TRANSPORT").unwrap_or_else(|_| "auto".to_string())
}

pub fn max_concurrent_syncs() -> usize {
    env::var("GITP2P_MAX_CONCURRENT_SYNCS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
}

pub fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    seconds.to_string()
}

pub fn compact_timestamp() -> String {
    timestamp()
}

pub fn hostname() -> String {
    env::var("HOSTNAME")
        .or_else(|_| env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "local".to_string())
}

pub fn stable_id(input: &str) -> String {
    let mut hash: u64 = 14695981039346656037;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("{hash:016x}")
}

pub fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('=', "\\e")
}

pub fn unescape(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('e') => out.push('='),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

pub fn empty_dash(value: &str) -> &str {
    if value.is_empty() {
        "-"
    } else {
        value
    }
}

pub fn append_log(vault: &Vault, line: &str) -> Result<()> {
    let path = vault.path.join("logs").join("events.log");
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{} {}", timestamp(), line)?;
    Ok(())
}

pub fn append_replication_log(vault: &Vault, peer_id: &str, repo_id: &str, line: &str) -> Result<()> {
    let path = vault
        .path
        .join("logs")
        .join(format!("replication-{peer_id}-{repo_id}.log"));
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{} {}", timestamp(), line)?;
    Ok(())
}

pub fn count_files(path: PathBuf) -> Result<usize> {
    if !path.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in fs::read_dir(path)? {
        if entry?.file_type()?.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

pub fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(String::from)
        .collect()
}

pub fn contains_csv(value: &str, item: &str) -> bool {
    split_csv(value).iter().any(|part| part == item)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_are_repeatable() {
        assert_eq!(stable_id("aeva"), stable_id("aeva"));
        assert_ne!(stable_id("aeva"), stable_id("other"));
    }

    #[test]
    fn metadata_escape_roundtrips() {
        let original = "a=b\\c\nnext";
        assert_eq!(unescape(&escape(original)), original);
    }
}
