//! Unit Tests for FIDO2/WebAuthn Server
//! 
//! This module contains comprehensive unit tests for all core components:
//! - Services layer
//! - Controllers layer  
//! - Database repositories
//! - Utility functions
//! - Error handling

pub mod services;
pub mod controllers;
pub mod db;
pub mod utils;
pub mod error;

use crate::common::test_setup::*;

#[cfg(test)]
mod integration_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_unit_test_framework_setup() {
        let context = setup_test().await;
        
        // Verify test environment is properly configured
        assert!(!context.database_url.is_empty());
        assert!(context.config.get("webauthn").is_some());
        
        cleanup_test(context).await;
    }
}