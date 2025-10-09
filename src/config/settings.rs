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
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // TODO: Implement proper configuration loading
        // This is a placeholder implementation
        Ok(Self {
            server: ServerSettings {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            database: DatabaseSettings {
                url: "postgres://localhost/fido_server".to_string(),
                max_pool_size: 10,
            },
            webauthn: WebAuthnSettings {
                rp_id: "localhost".to_string(),
                rp_name: "FIDO Server".to_string(),
                origin: "http://localhost:8080".to_string(),
            },
        })
    }
}
