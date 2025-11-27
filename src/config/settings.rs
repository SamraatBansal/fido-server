//! Application settings and configuration

use config::{Config, ConfigError, Environment};
use serde::Deserialize;
use std::env;

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
    /// Pool timeout in seconds
    pub timeout_seconds: u64,
    /// Idle timeout in seconds
    pub idle_timeout_seconds: u64,
    /// SSL mode (require, prefer, allow, disable)
    pub ssl_mode: String,
}

/// Redis settings
#[derive(Debug, Deserialize, Clone)]
pub struct RedisSettings {
    /// Redis URL
    pub url: String,
    /// Maximum pool size
    pub max_size: u32,
    /// Connection timeout in seconds
    pub timeout_seconds: u64,
    /// Connection recycle timeout in seconds
    pub recycle_timeout_seconds: u64,
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
    pub fn new() -> Result<Self, ConfigError> {
        // Load .env file if it exists
        dotenvy::dotenv().ok();

        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            // Start with default configuration
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("database.max_pool_size", 10)?
            .set_default("database.timeout_seconds", 30)?
            .set_default("database.idle_timeout_seconds", 600)?
            .set_default("database.ssl_mode", if run_mode == "production" { "require" } else { "prefer" })?
            .set_default("redis.max_size", 10)?
            .set_default("redis.timeout_seconds", 30)?
            .set_default("redis.recycle_timeout_seconds", 300)?
            .set_default("webauthn.rp_id", "localhost")?
            .set_default("webauthn.rp_name", "FIDO Server")?
            .set_default("webauthn.origin", "http://localhost:8080")?
            // Add environment variables with prefix
            .add_source(Environment::with_prefix("FIDO").separator("_"))
            .build()?;

        let mut settings: Settings = s.try_deserialize()?;

        // Validate required environment variables
        settings.validate()?;

        Ok(settings)
    }

    /// Validate configuration settings
    ///
    /// # Errors
    ///
    /// Returns an error if configuration is invalid
    fn validate(&mut self) -> Result<(), ConfigError> {
        // Ensure database URL is set
        if self.database.url.is_empty() {
            return Err(ConfigError::Message("DATABASE_URL environment variable is required".to_string()));
        }

        // Ensure Redis URL is set
        if self.redis.url.is_empty() {
            return Err(ConfigError::Message("REDIS_URL environment variable is required".to_string()));
        }

        // Validate SSL mode
        if !["require", "prefer", "allow", "disable"].contains(&self.database.ssl_mode.as_str()) {
            return Err(ConfigError::Message("Invalid database SSL mode. Must be one of: require, prefer, allow, disable".to_string()));
        }

        // Ensure WebAuthn origin matches server configuration
        if self.webauthn.origin == "http://localhost:8080" {
            self.webauthn.origin = format!("http://{}:{}", self.server.host, self.server.port);
        }

        Ok(())
    }
}
