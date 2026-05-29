pub mod metadata;
pub mod identity;
pub mod trust;
pub mod vault;

pub use metadata::{AppError, Result, VERSION};
pub use metadata::*;
pub use metadata::util;
pub use identity::*;
pub use trust::*;
pub use vault::{App, checkpoints_for_repo, checkpoints_for_vault, latest_checkpoint, write_session};
pub use vault::{checkpoint_lineage, copy_checkpoint_if_missing, create_checkpoint, validate_checkpoint_for_sync};
pub use vault::{prune_checkpoints, create_vault, delete_vault, ensure_remote_vault};
pub use vault::{add_repo, remove_repo, register_imported_repo};
pub use vault::app;
pub use vault::layout;
