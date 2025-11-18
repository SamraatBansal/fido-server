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
}

impl Settings {
    /// Load settings from environment variables and config files
    ///
    /// # Errors
    ///
    /// Returns an error if configuration cannot be loaded
    pub fn new() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("FIDO_SERVER"))
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("database.url", "postgres://localhost/fido_server")?
            .set_default("database.max_pool_size", 10)?
            .set_default("webauthn.rp_id", "localhost")?
            .set_default("webauthn.rp_name", "FIDO Server")?
            .set_default("webauthn.origin", "http://localhost:8080")?
            .build()?;

        settings.try_deserialize()
    }
}
