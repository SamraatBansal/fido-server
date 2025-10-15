//! WebAuthn Configuration
//! 
//! Configuration for FIDO2/WebAuthn server with security-focused defaults

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

/// WebAuthn configuration with security defaults
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party configuration
    pub rp: RelyingParty,
    /// Security settings
    pub security: SecurityConfig,
    /// Attestation preferences
    pub attestation: AttestationConfig,
}

/// Relying Party configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    /// RP ID (must match domain)
    pub id: String,
    /// RP name for display
    pub name: String,
    /// RP origin URLs
    pub origins: Vec<String>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Challenge expiration time in seconds
    pub challenge_expiration: u64,
    /// Maximum failed attempts per minute
    pub max_failed_attempts: u32,
    /// Require user verification
    pub require_user_verification: bool,
    /// Allowed algorithms
    pub allowed_algorithms: Vec<COSEAlgorithm>,
}

/// Attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// Default attestation preference
    pub preference: AttestationConveyancePreference,
    /// Supported attestation formats
    pub supported_formats: Vec<AttestationFormat>,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp: RelyingParty {
                id: "localhost".to_string(),
                name: "FIDO Server".to_string(),
                origins: vec!["https://localhost:8080".to_string()],
            },
            security: SecurityConfig {
                challenge_expiration: 300, // 5 minutes
                max_failed_attempts: 5,
                require_user_verification: true,
                allowed_algorithms: vec![
                    COSEAlgorithm::ES256,
                    COSEAlgorithm::RS256,
                    COSEAlgorithm::EdDSA,
                ],
            },
            attestation: AttestationConfig {
                preference: AttestationConveyancePreference::Direct,
                supported_formats: vec![
                    AttestationFormat::Packed,
                    AttestationFormat::FidoU2f,
                    AttestationFormat::None,
                ],
            },
        }
    }
}

impl WebAuthnConfig {
    /// Create WebAuthn instance from configuration
    pub fn create_webauthn(&self) -> Result<WebAuthn, WebauthnError> {
        WebAuthn::new(
            &self.rp.id,
            &self.rp.name,
            &self.rp.origins,
            self.security.allowed_algorithms.clone(),
        )
    }

    /// Validate configuration for security compliance
    pub fn validate(&self) -> Result<(), String> {
        // Validate RP ID format
        if self.rp.id.is_empty() {
            return Err("RP ID cannot be empty".to_string());
        }

        // Validate origins
        if self.rp.origins.is_empty() {
            return Err("At least one origin must be specified".to_string());
        }

        // Validate security settings
        if self.security.challenge_expiration > 600 {
            return Err("Challenge expiration should not exceed 10 minutes".to_string());
        }

        if self.security.max_failed_attempts > 20 {
            return Err("Max failed attempts should not exceed 20".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_validation() {
        let config = WebAuthnConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_rp_id() {
        let mut config = WebAuthnConfig::default();
        config.rp.id = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_challenge_expiration_limit() {
        let mut config = WebAuthnConfig::default();
        config.security.challenge_expiration = 700; // Exceeds 10 minutes
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_webauthn_creation() {
        let config = WebAuthnConfig::default();
        assert!(config.create_webauthn().is_ok());
    }
}