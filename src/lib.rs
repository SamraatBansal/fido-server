//! FIDO2/WebAuthn Relying Party Server Library
//! 
//! A production-ready FIDO2/WebAuthn server library that passes FIDO Alliance conformance tests.

pub mod error;
pub mod storage;
pub mod handlers;
pub mod dto;
pub mod utils;

pub use error::WebAuthnError;
pub use storage::{Storage, InMemoryStorage, UserInfo, CredentialInfo, ChallengeInfo, ChallengeState};
pub use handlers::*;

/// Re-export common types for convenience
pub mod prelude {
    pub use crate::error::WebAuthnError;
    pub use crate::storage::{Storage, InMemoryStorage};
    pub use crate::dto::*;
    pub use webauthn_rs::prelude::*;
}