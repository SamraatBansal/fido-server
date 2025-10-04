//! Application settings and configuration

use serde::Deserialize;

/// Application settings
#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// Server configuration
    pub server: ServerSettings,
    /// Database configuration
    pub database: DatabaseSettings,
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
    /// Challenge time-to-live in seconds
    pub challenge_ttl_seconds: u64,
    /// Attestation preference
    pub attestation_preference: String,
    /// User verification policy
    pub user_verification: String,
    /// Resident key requirement
    pub resident_key_requirement: String,
}

impl Settings {
    /// Load settings from environment variables and config files
    ///
    /// # Errors
    ///
    /// Returns an error if configuration cannot be loaded
    pub fn new() -> Result<Self, config::ConfigError> {
        let mut settings = config::Config::builder();
        
        // Load default settings
        settings = settings
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("database.max_pool_size", 10)?
            .set_default("webauthn.challenge_ttl_seconds", 300)?
            .set_default("webauthn.attestation_preference", "direct")?
            .set_default("webauthn.user_verification", "required")?
            .set_default("webauthn.resident_key_requirement", "preferred")?;

        // Load from .env file
        dotenv::dotenv().ok();
        
        // Load from environment variables
        settings = settings
            .add_source(config::Environment::with_prefix("FIDO_SERVER"))
            .add_source(config::File::with_name("config/default").required(false))
            .add_source(config::File::with_name("config/local").required(false));

        let config = settings.build()?;
        
        Ok(config.try_deserialize()?)
    }
}
