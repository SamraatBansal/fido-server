//! Controllers module

pub mod authentication;
pub mod health;
pub mod registration;
pub mod webauthn;

pub use authentication::AuthenticationController;
pub use health::HealthController;
pub use registration::RegistrationController;
pub use webauthn::WebAuthnController;