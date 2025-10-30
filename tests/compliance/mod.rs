//! FIDO2 compliance tests

pub mod fido2_registration_tests;
pub mod fido2_authentication_tests;
pub mod attestation_tests;
pub mod webauthn_api_tests;

pub use fido2_registration_tests::*;
pub use fido2_authentication_tests::*;
pub use attestation_tests::*;
pub use webauthn_api_tests::*;