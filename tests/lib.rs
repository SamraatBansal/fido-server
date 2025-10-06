//! FIDO2/WebAuthn Server Test Suite
//! 
//! This module provides comprehensive testing for the FIDO2/WebAuthn Relying Party Server,
//! covering unit tests, integration tests, security tests, performance tests, and compliance tests.

pub mod common;
pub mod unit;
pub mod integration;
pub mod security;
pub mod performance;
pub mod compliance;

// Re-export common test utilities
pub use common::{
    fixtures::TestFixtures,
    helpers::{setup_test_db, cleanup_test_db, create_test_app},
    mocks::{MockWebAuthnService, MockSecurityService, MockUserRepository},
};

// Test configuration
pub const TEST_RP_ID: &str = "localhost";
pub const TEST_RP_NAME: &str = "FIDO2 Test Server";
pub const TEST_ORIGIN: &str = "https://localhost:8443";

/// Test result type for convenience
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Common test setup macro
#[macro_export]
macro_rules! setup_test {
    () => {
        let _test_env = $crate::common::helpers::TestEnvironment::setup().await;
    };
}

/// Async test wrapper macro
#[macro_export]
macro_rules! async_test {
    ($test_name:ident, $test_body:block) => {
        #[tokio::test]
        async fn $test_name() -> $crate::TestResult {
            setup_test!();
            $test_body
            Ok(())
        }
    };
}