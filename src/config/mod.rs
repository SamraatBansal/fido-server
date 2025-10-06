//! WebAuthn Configuration Module

use serde::{Deserialize, Serialize};
use std::time::Duration;
use webauthn_rs::prelude::*;

/// WebAuthn configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party identifier (e.g., "example.com")
    pub rp_id: String,
    /// Relying Party name (e.g., "Example Inc.")
    pub rp_name: String,
    /// Relying Party origin (e.g., "https://example.com")
    pub rp_origin: String,
    /// Timeout for WebAuthn operations in milliseconds
    pub timeout: u64,
    /// Attestation conveyance preference
    pub attestation_preference: AttestationConveyancePreference,
    /// User verification requirement
    pub user_verification: UserVerificationPolicy,
    /// Challenge expiration time in seconds
    pub challenge_ttl: u64,
    /// Session expiration time in seconds
    pub session_ttl: u64,
    /// Maximum number of credentials per user
    pub max_credentials_per_user: usize,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "FIDO Server".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: 60000, // 60 seconds
            attestation_preference: AttestationConveyancePreference::None,
            user_verification: UserVerificationPolicy::Preferred,
            challenge_ttl: 300, // 5 minutes
            session_ttl: 3600,  // 1 hour
            max_credentials_per_user: 10,
        }
    }
}

impl WebAuthnConfig {
    /// Create WebAuthn instance from configuration
    pub fn create_webauthn(&self) -> Result<WebAuthn, webauthn_rs::error::WebauthnError> {
        let rp = RelyingParty {
            id: self.rp_id.clone(),
            name: self.rp_name.clone(),
            origin: Url::parse(&self.rp_origin)
                .map_err(|_| webauthn_rs::error::WebauthnError::Configuration)?,
        };

        WebAuthn::new(
            rp,
            self.attestation_preference,
            self.user_verification,
        )
    }

    /// Get timeout duration
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_millis(self.timeout)
    }

    /// Get challenge expiration duration
    pub fn challenge_ttl_duration(&self) -> Duration {
        Duration::from_secs(self.challenge_ttl)
    }

    /// Get session expiration duration
    pub fn session_ttl_duration(&self) -> Duration {
        Duration::from_secs(self.session_ttl)
    }
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Server configuration
    pub server: ServerConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Number of worker threads
    pub workers: Option<usize>,
    /// Enable TLS
    pub tls_enabled: bool,
    /// TLS certificate file path
    pub tls_cert_path: Option<String>,
    /// TLS private key file path
    pub tls_key_path: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: None,
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Minimum number of connections in the pool
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Idle timeout in seconds
    pub idle_timeout: Option<u64>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://fido_user:fido_pass@localhost/fido_db".to_string(),
            max_connections: 10,
            min_connections: 1,
            connection_timeout: 30,
            idle_timeout: Some(600),
        }
    }
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// JWT secret key
    pub jwt_secret: String,
    /// JWT algorithm
    pub jwt_algorithm: String,
    /// Rate limit requests per minute
    pub rate_limit_rpm: u32,
    /// Maximum request body size in bytes
    pub max_request_size: usize,
    /// Enable CORS
    pub cors_enabled: bool,
    /// Allowed origins
    pub allowed_origins: Vec<String>,
    /// Enable HSTS
    pub hsts_enabled: bool,
    /// HSTS max age in seconds
    pub hsts_max_age: u64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "your-super-secret-jwt-key-change-in-production".to_string(),
            jwt_algorithm: "HS256".to_string(),
            rate_limit_rpm: 60,
            max_request_size: 1024 * 1024, // 1MB
            cors_enabled: true,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            hsts_enabled: false,
            hsts_max_age: 31536000, // 1 year
        }
    }
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    pub level: String,
    /// Enable JSON logging
    pub json_format: bool,
    /// Enable tracing
    pub tracing_enabled: bool,
    /// Log file path (optional)
    pub file_path: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            json_format: false,
            tracing_enabled: true,
            file_path: None,
        }
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            webauthn: WebAuthnConfig::default(),
            security: SecurityConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Load configuration from environment variables and config file
pub fn load_config() -> Result<AppConfig, config::ConfigError> {
    let mut settings = config::Config::builder();

    // Start with default configuration
    settings = settings.add_source(config::Config::try_from(&AppConfig::default())?);

    // Add environment file if it exists
    if std::path::Path::new(".env").exists() {
        settings = settings.add_source(config::File::with_name(".env"));
    }

    // Override with environment variables
    settings = settings.add_source(config::Environment::with_prefix("FIDO"));

    let config = settings.build()?.try_deserialize::<AppConfig>()?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_config_default() {
        let config = WebAuthnConfig::default();
        assert_eq!(config.rp_id, "localhost");
        assert_eq!(config.timeout, 60000);
        assert_eq!(config.challenge_ttl, 300);
    }

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.webauthn.rp_name, "FIDO Server");
    }

    #[test]
    fn test_timeout_duration() {
        let config = WebAuthnConfig::default();
        let duration = config.timeout_duration();
        assert_eq!(duration, Duration::from_millis(60000));
    }
}