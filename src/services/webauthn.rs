//! WebAuthn service

use crate::config::webauthn::WebAuthnConfig;
use crate::error::{AppError, Result};
use uuid::Uuid;
use std::collections::HashMap;

/// WebAuthn service for handling FIDO2 operations
pub struct WebAuthnService {
    config: WebAuthnConfig,
    // In-memory storage for states (in production, use Redis)
    registration_states: HashMap<Uuid, String>,
    authentication_states: HashMap<Uuid, String>,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        Ok(Self {
            config,
            registration_states: HashMap::new(),
            authentication_states: HashMap::new(),
        })
    }

    /// Get WebAuthn configuration
    pub fn config(&self) -> &WebAuthnConfig {
        &self.config
    }

    /// Validate origin
    pub fn validate_origin(&self, origin: &str) -> Result<()> {
        self.config.validate_origin(origin)
    }

    // TODO: Implement WebAuthn operations
    // - start_registration
    // - finish_registration  
    // - start_authentication
    // - finish_authentication
}