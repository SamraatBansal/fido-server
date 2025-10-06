//! Common test utilities and fixtures
//! 
//! This module provides shared testing infrastructure including:
//! - Test fixtures for common data
//! - Mock implementations
//! - Helper functions for test setup
//! - Test configuration

pub mod fixtures;
pub mod helpers;
pub mod mocks;

// Re-export commonly used items
pub use fixtures::TestFixtures;
pub use helpers::{TestEnvironment, setup_test_db, cleanup_test_db};
pub use mocks::{MockWebAuthnService, MockSecurityService, MockUserRepository};

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Common test configuration
pub struct TestConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub database_url: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "FIDO2 Test Server".to_string(),
            origin: "https://localhost:8443".to_string(),
            database_url: "postgresql://test:test@localhost/test".to_string(),
        }
    }
}

/// Test context for sharing state between tests
pub struct TestContext {
    pub config: TestConfig,
    pub fixtures: TestFixtures,
    pub shared_state: Arc<RwLock<HashMap<String, String>>>,
}

impl TestContext {
    pub fn new() -> Self {
        Self {
            config: TestConfig::default(),
            fixtures: TestFixtures::new(),
            shared_state: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

/// Result type for test functions
pub type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Macro for setting up test environment
#[macro_export]
macro_rules! setup_test_env {
    () => {
        let _test_env = $crate::common::TestEnvironment::setup().await;
    };
}

/// Macro for async test with cleanup
#[macro_export]
macro_rules! async_test_with_cleanup {
    ($test_name:ident, $test_body:block) => {
        #[tokio::test]
        async fn $test_name() -> $crate::TestResult {
            let test_env = $crate::common::TestEnvironment::setup().await;
            
            // Execute test
            let result = async move {
                $test_body
                Ok::<(), Box<dyn std::error::Error>>(())
            }.await;
            
            // Cleanup
            test_env.cleanup().await;
            result
        }
    };
}