pub mod error;
pub mod git;
pub mod kv;
pub mod models;
pub mod util;

pub use error::{AppError, Result};
pub use kv::{field, optional_field, read_kv, write_kv, write_kv_atomic};
pub use models::*;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
