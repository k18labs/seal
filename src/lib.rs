#![forbid(unsafe_code)]

pub mod hash;
pub mod manifest;
pub mod signature;
pub mod tree;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
