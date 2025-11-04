//! Database schema module

pub mod user;
pub mod credential;
pub mod challenge;

// Include the Diesel-generated schema
include!("diesel_schema.rs");

pub use user::*;
pub use credential::*;
pub use challenge::*;