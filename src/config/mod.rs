//! Configuration management

use serde::{Deserialize, Serialize};
use std::env;

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
    pub min_connections: Option<u32>,
    pub connection_timeout: Option<u32>,
}

/// WebAuthn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: Option<u32>,
    pub attestation_preference: webauthn_rs_proto::AttestationConveyancePreference,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub challenge_expiry_seconds: u64,
    pub max_concurrent_requests: usize,
    pub rate_limit_requests_per_minute: u32,
    pub cors_origins: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: None,
            },
            database: DatabaseConfig {
                url: "postgres://localhost/fido_server".to_string(),
                max_connections: Some(10),
                min_connections: Some(1),
                connection_timeout: Some(30),
            },
            webauthn: WebAuthnConfig {
                rp_name: "FIDO Server".to_string(),
                rp_id: "localhost".to_string(),
                rp_origin: "http://localhost:8080".to_string(),
                timeout: Some(60000),
                attestation_preference: webauthn_rs_proto::AttestationConveyancePreference::Direct,
            },
            security: SecurityConfig {
                challenge_expiry_seconds: 300, // 5 minutes
                max_concurrent_requests: 100,
                rate_limit_requests_per_minute: 60,
                cors_origins: vec!["http://localhost:3000".to_string()],
            },
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Self::default();

        // Server configuration
        if let Ok(host) = env::var("SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = env::var("SERVER_PORT") {
            config.server.port = port.parse()?;
        }
        if let Ok(workers) = env::var("SERVER_WORKERS") {
            config.server.workers = Some(workers.parse()?);
        }

        // Database configuration
        if let Ok(database_url) = env::var("DATABASE_URL") {
            config.database.url = database_url;
        }
        if let Ok(max_connections) = env::var("DATABASE_MAX_CONNECTIONS") {
            config.database.max_connections = Some(max_connections.parse()?);
        }
        if let Ok(min_connections) = env::var("DATABASE_MIN_CONNECTIONS") {
            config.database.min_connections = Some(min_connections.parse()?);
        }
        if let Ok(connection_timeout) = env::var("DATABASE_CONNECTION_TIMEOUT") {
            config.database.connection_timeout = Some(connection_timeout.parse()?);
        }

        // WebAuthn configuration
        if let Ok(rp_name) = env::var("WEBAUTHN_RP_NAME") {
            config.webauthn.rp_name = rp_name;
        }
        if let Ok(rp_id) = env::var("WEBAUTHN_RP_ID") {
            config.webauthn.rp_id = rp_id;
        }
        if let Ok(rp_origin) = env::var("WEBAUTHN_RP_ORIGIN") {
            config.webauthn.rp_origin = rp_origin;
        }
        if let Ok(timeout) = env::var("WEBAUTHN_TIMEOUT") {
            config.webauthn.timeout = Some(timeout.parse()?);
        }

        // Security configuration
        if let Ok(challenge_expiry) = env::var("SECURITY_CHALLENGE_EXPIRY_SECONDS") {
            config.security.challenge_expiry_seconds = challenge_expiry.parse()?;
        }
        if let Ok(max_concurrent) = env::var("SECURITY_MAX_CONCURRENT_REQUESTS") {
            config.security.max_concurrent_requests = max_concurrent.parse()?;
        }
        if let Ok(rate_limit) = env::var("SECURITY_RATE_LIMIT_REQUESTS_PER_MINUTE") {
            config.security.rate_limit_requests_per_minute = rate_limit.parse()?;
        }
        if let Ok(cors_origins) = env::var("SECURITY_CORS_ORIGINS") {
            config.security.cors_origins = cors_origins.split(',').map(|s| s.trim().to_string()).collect();
        }

        Ok(config)
    }
}