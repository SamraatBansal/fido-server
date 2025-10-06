//! Data transfer objects (DTOs)

pub mod requests;
pub mod responses;
pub mod webauthn;

pub use requests::*;
pub use responses::*;
pub use webauthn::*;

// Re-export the generated schema
pub use crate::schema::generated::*;