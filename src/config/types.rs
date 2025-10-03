//! Configuration types

use serde::{Deserialize, Serialize};
use std::env;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Database URL
    pub database_url: String,
    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,
    /// Security settings
    pub security: SecurityConfig,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party name
    pub rp_name: String,
    /// Relying party ID
    pub rp_id: String,
    /// Relying party origin
    pub rp_origin: String,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable TLS
    pub tls_enabled: bool,
    /// TLS certificate path
    pub tls_cert_path: Option<String>,
    /// TLS private key path
    pub tls_key_path: Option<String>,
    /// Rate limit requests per minute
    pub rate_limit_rpm: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .unwrap_or(8080),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/fido_server".to_string()),
            webauthn: WebAuthnConfig {
                rp_name: env::var("RP_NAME")
                    .unwrap_or_else(|_| "FIDO Server".to_string()),
                rp_id: env::var("RP_ID")
                    .unwrap_or_else(|_| "localhost".to_string()),
                rp_origin: env::var("RP_ORIGIN")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            },
            security: SecurityConfig {
                tls_enabled: env::var("TLS_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()
                    .unwrap_or(false),
                tls_cert_path: env::var("TLS_CERT_PATH").ok(),
                tls_key_path: env::var("TLS_KEY_PATH").ok(),
                rate_limit_rpm: env::var("RATE_LIMIT_RPM")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()
                    .unwrap_or(60),
            },
        }
    }
}