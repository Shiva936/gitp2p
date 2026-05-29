use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{AppError, Result};
use super::util::{create_dir_all, escape, unescape};

pub fn read_kv(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut file = File::open(path)?;
    let mut input = String::new();
    file.read_to_string(&mut input)?;
    let mut map = BTreeMap::new();
    for line in input.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            AppError::new(format!(
                "invalid metadata line in '{}': {line}",
                path.display()
            ))
        })?;
        map.insert(key.to_string(), unescape(value));
    }
    Ok(map)
}

pub fn write_kv(path: &Path, values: &[(&str, &str)]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let temp = path.with_extension("tmp");
    {
        let mut file = File::create(&temp)?;
        for (key, value) in values {
            writeln!(file, "{}={}", key, escape(value))?;
        }
        file.sync_all()?;
    }
    fs::rename(temp, path)?;
    Ok(())
}

pub fn write_kv_atomic(path: &Path, values: &[(&str, &str)]) -> Result<()> {
    write_kv(path, values)
}

pub fn field(map: &BTreeMap<String, String>, key: &str) -> Result<String> {
    map.get(key)
        .cloned()
        .ok_or_else(|| AppError::new(format!("metadata missing '{key}'")))
}

pub fn optional_field(map: &BTreeMap<String, String>, key: &str) -> String {
    map.get(key).cloned().unwrap_or_default()
}
