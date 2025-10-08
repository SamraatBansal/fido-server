//! Request/Response schema module

pub mod webauthn;

pub use webauthn::*;

// Re-export the schema for database models
pub use crate::schema::*;