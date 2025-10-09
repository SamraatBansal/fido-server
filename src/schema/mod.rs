//! Request and response schemas for FIDO2/WebAuthn APIs

use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

pub mod attestation;
pub mod assertion;
pub mod common;

pub use attestation::*;
pub use assertion::*;
pub use common::*;