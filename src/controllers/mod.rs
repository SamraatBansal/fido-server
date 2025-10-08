//! Controllers module

pub mod authentication;
pub mod health;
pub mod registration;

pub use authentication::{AuthenticationController, start_assertion, verify_assertion};
pub use health::{HealthController, health_check};
pub use registration::{RegistrationController, start_attestation, verify_attestation};