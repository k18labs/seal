#![forbid(unsafe_code)]

pub mod hash;
pub mod signature;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
