//! Configuration management for FIDO Server

use serde::{Deserialize, Serialize};
use std::env;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server configuration
    pub server: ServerConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// WebAuthn configuration
    pub webauthn: WebAuthnConfig,
    /// Security configuration
    pub security: SecurityConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server host
    pub host: String,
    /// Server port
    pub port: u16,
    /// Allowed origins for CORS
    pub allowed_origins: Vec<String>,
    /// Enable TLS
    pub tls_enabled: bool,
    /// TLS certificate path (if enabled)
    pub tls_cert_path: Option<String>,
    /// TLS private key path (if enabled)
    pub tls_key_path: Option<String>,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL
    pub url: String,
    /// Maximum number of connections
    pub max_connections: u32,
    /// Minimum number of connections
    pub min_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying Party ID
    pub rp_id: String,
    /// Relying Party name
    pub rp_name: String,
    /// Relying Party origin
    pub rp_origin: String,
    /// Challenge timeout in seconds
    pub challenge_timeout: u64,
    /// Require user verification
    pub require_user_verification: bool,
    /// Attestation preference
    pub attestation_preference: String,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Rate limit requests per minute
    pub rate_limit_per_minute: u32,
    /// Session timeout in seconds
    pub session_timeout: u64,
    /// Enable HSTS
    pub enable_hsts: bool,
    /// HSTS max age in seconds
    pub hsts_max_age: u64,
    /// Enable CSRF protection
    pub enable_csrf: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            webauthn: WebAuthnConfig::default(),
            security: SecurityConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            allowed_origins: vec!["http://localhost:3000".to_string()],
            tls_enabled: false,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/fido_server".to_string(),
            max_connections: 10,
            min_connections: 1,
            connection_timeout: 30,
        }
    }
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "FIDO Server".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            challenge_timeout: 300, // 5 minutes
            require_user_verification: false,
            attestation_preference: "direct".to_string(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            rate_limit_per_minute: 60,
            session_timeout: 3600, // 1 hour
            enable_hsts: true,
            hsts_max_age: 31536000, // 1 year
            enable_csrf: true,
        }
    }
}

/// Load configuration from environment variables and config file
pub fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    // Load from .env file if it exists
    dotenv::dotenv().ok();

    let mut config = Config::default();

    // Override with environment variables
    if let Ok(host) = env::var("SERVER_HOST") {
        config.server.host = host;
    }
    if let Ok(port) = env::var("SERVER_PORT") {
        config.server.port = port.parse()?;
    }
    if let Ok(database_url) = env::var("DATABASE_URL") {
        config.database.url = database_url;
    }
    if let Ok(rp_id) = env::var("RP_ID") {
        config.webauthn.rp_id = rp_id;
    }
    if let Ok(rp_name) = env::var("RP_NAME") {
        config.webauthn.rp_name = rp_name;
    }
    if let Ok(rp_origin) = env::var("RP_ORIGIN") {
        config.webauthn.rp_origin = rp_origin;
    }

    // Try to load from config file
    if let Ok(config_path) = env::var("CONFIG_PATH") {
        let config_content = std::fs::read_to_string(config_path)?;
        let file_config: Config = toml::from_str(&config_content)?;
        // Merge file config with defaults (file takes precedence)
        config = file_config;
    }

    Ok(config)
}