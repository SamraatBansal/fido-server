//! Domain models for the FIDO2/WebAuthn server

pub mod user;
pub mod credential;
pub mod challenge;

pub use user::User;
pub use credential::Credential;
pub use challenge::{Challenge, ChallengeType};