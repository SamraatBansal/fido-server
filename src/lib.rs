pub mod api;
pub mod error;
pub mod models;
pub mod security;
pub mod storage;
pub mod webauthn;

pub use error::{FidoError, Result};
pub use models::{User, Credential, Challenge};

// Re-export commonly used types
pub use webauthn_rs::{
    prelude::*,
    Webauthn,
    WebauthnBuilder,
};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info() {
        assert!(!VERSION.is_empty());
        assert_eq!(NAME, "fido-server3");
    }
}