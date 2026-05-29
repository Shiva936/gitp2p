use std::path::{Path, PathBuf};

use gitp2p_metadata::{AppError, Result};
use gitp2p_metadata::util::create_dir_all;

pub fn validate_media_path(path: &Path) -> Result<PathBuf> {
    if !path.exists() {
        return Err(AppError::new(format!(
            "media path '{}' does not exist",
            path.display()
        )));
    }
    let canonical = path.canonicalize()?;
    Ok(canonical)
}

pub fn media_export(source: &Path, media_root: &Path) -> Result<PathBuf> {
    let validated = validate_media_path(media_root)?;
    let dest = validated.join(source.file_name().ok_or_else(|| {
        AppError::new("source has no file name")
    })?);
    create_dir_all(validated)?;
    std::fs::copy(source, &dest)?;
    Ok(dest)
}

pub fn media_import(media_root: &Path, name: &str) -> Result<PathBuf> {
    let validated = validate_media_path(media_root)?;
    let path = validated.join(name);
    if !path.exists() {
        return Err(AppError::new(format!(
            "media artifact '{}' not found on removable media",
            path.display()
        )));
    }
    Ok(path)
}
