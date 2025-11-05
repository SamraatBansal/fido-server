//! WebAuthn configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party name
    pub rp_name: String,
    /// Relying party ID
    pub rp_id: String,
    /// Relying party origin
    pub rp_origin: String,
    /// Challenge timeout in milliseconds
    pub timeout: u64,
    /// Require user verification
    pub require_user_verification: bool,
    /// Supported algorithms
    pub supported_algorithms: Vec<i32>,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: 60000,
            require_user_verification: false,
            supported_algorithms: vec![crate::webauthn::ALG_ES256, crate::webauthn::ALG_RS256],
        }
    }
}

impl WebAuthnConfig {
    /// Create new WebAuthn configuration
    pub fn new(
        rp_name: impl Into<String>,
        rp_id: impl Into<String>,
        rp_origin: impl Into<String>,
    ) -> Self {
        Self {
            rp_name: rp_name.into(),
            rp_id: rp_id.into(),
            rp_origin: rp_origin.into(),
            ..Default::default()
        }
    }

    /// Get timeout as Duration
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.timeout)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.rp_name.is_empty() {
            return Err("RP name cannot be empty".to_string());
        }
        if self.rp_id.is_empty() {
            return Err("RP ID cannot be empty".to_string());
        }
        if self.rp_origin.is_empty() {
            return Err("RP origin cannot be empty".to_string());
        }
        if self.timeout == 0 {
            return Err("Timeout must be greater than 0".to_string());
        }
        if self.supported_algorithms.is_empty() {
            return Err("At least one supported algorithm is required".to_string());
        }
        Ok(())
    }
}