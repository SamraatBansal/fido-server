//! Controllers module

pub mod registration;
pub mod authentication;
pub mod health;

pub use registration::RegistrationController;
pub use authentication::AuthenticationController;
pub use health::HealthController;