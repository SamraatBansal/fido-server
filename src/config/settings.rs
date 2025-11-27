//! Application settings and configuration

use serde::Deserialize;
use std::env;
use log;

/// Application settings
#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// Server configuration
    pub server: ServerSettings,
    /// Database configuration
    pub database: DatabaseSettings,
    /// Redis configuration
    pub redis: RedisSettings,
    /// WebAuthn configuration
    pub webauthn: WebAuthnSettings,
}

/// Server settings
#[derive(Debug, Deserialize, Clone)]
pub struct ServerSettings {
    /// Host address
    pub host: String,
    /// Port number
    pub port: u16,
}

/// Database settings
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseSettings {
    /// Database URL
    pub url: String,
    /// Maximum pool size
    pub max_pool_size: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Idle timeout in seconds
    pub idle_timeout: u64,
}

/// Redis settings
#[derive(Debug, Deserialize, Clone)]
pub struct RedisSettings {
    /// Redis URL
    pub url: String,
    /// Maximum pool size
    pub max_pool_size: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Command timeout in seconds
    pub command_timeout: u64,
    /// TTL for session data in seconds
    pub session_ttl: u64,
}

/// WebAuthn settings
#[derive(Debug, Deserialize, Clone)]
pub struct WebAuthnSettings {
    /// Relying party ID
    pub rp_id: String,
    /// Relying party name
    pub rp_name: String,
    /// Origin URL
    pub origin: String,
}

impl Settings {
    /// Load settings from environment variables and config files
    ///
    /// # Errors
    ///
    /// Returns an error if configuration cannot be loaded
    pub fn new() -> Result<Self, config::ConfigError> {
        // Load environment variables from .env file if present
        dotenv::dotenv().ok();
        
        let server = ServerSettings {
            host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid SERVER_PORT: {}", e)))?,
        };

        let database = DatabaseSettings {
            url: env::var("DATABASE_URL")
                .map_err(|_| config::ConfigError::Message("DATABASE_URL environment variable is required".to_string()))?,
            max_pool_size: env::var("DATABASE_MAX_POOL_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid DATABASE_MAX_POOL_SIZE: {}", e)))?,
            connection_timeout: env::var("DATABASE_CONNECTION_TIMEOUT")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid DATABASE_CONNECTION_TIMEOUT: {}", e)))?,
            idle_timeout: env::var("DATABASE_IDLE_TIMEOUT")
                .unwrap_or_else(|_| "600".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid DATABASE_IDLE_TIMEOUT: {}", e)))?,
        };

        let redis = RedisSettings {
            url: env::var("REDIS_URL")
                .map_err(|_| config::ConfigError::Message("REDIS_URL environment variable is required".to_string()))?,
            max_pool_size: env::var("REDIS_MAX_POOL_SIZE")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid REDIS_MAX_POOL_SIZE: {}", e)))?,
            connection_timeout: env::var("REDIS_CONNECTION_TIMEOUT")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid REDIS_CONNECTION_TIMEOUT: {}", e)))?,
            command_timeout: env::var("REDIS_COMMAND_TIMEOUT")
                .unwrap_or_else(|_| "3".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid REDIS_COMMAND_TIMEOUT: {}", e)))?,
            session_ttl: env::var("REDIS_SESSION_TTL")
                .unwrap_or_else(|_| "300".to_string())
                .parse()
                .map_err(|e| config::ConfigError::Message(format!("Invalid REDIS_SESSION_TTL: {}", e)))?,
        };

        let webauthn = WebAuthnSettings {
            rp_id: env::var("WEBAUTHN_RP_ID")
                .unwrap_or_else(|_| "localhost".to_string()),
            rp_name: env::var("WEBAUTHN_RP_NAME")
                .unwrap_or_else(|_| "FIDO Server".to_string()),
            origin: env::var("WEBAUTHN_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
        };

        Ok(Self {
            server,
            database,
            redis,
            webauthn,
        })
    }

    /// Validate configuration settings
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid
    pub fn validate(&self) -> Result<(), String> {
        // Validate database URL format
        if !self.database.url.starts_with("postgres://") && !self.database.url.starts_with("postgresql://") {
            return Err("DATABASE_URL must be a valid PostgreSQL URL".to_string());
        }

        // Validate Redis URL format
        if !self.redis.url.starts_with("redis://") && !self.redis.url.starts_with("rediss://") {
            return Err("REDIS_URL must be a valid Redis URL".to_string());
        }

        // Validate WebAuthn origin
        if !self.webauthn.origin.starts_with("http://") && !self.webauthn.origin.starts_with("https://") {
            return Err("WEBAUTHN_ORIGIN must be a valid HTTP or HTTPS URL".to_string());
        }

        Ok(())
    }
}
