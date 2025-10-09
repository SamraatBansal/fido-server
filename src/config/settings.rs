//! Application settings

use serde::{Deserialize, Serialize};

/// Application settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub webauthn: WebAuthnSettings,
    pub database: DatabaseSettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerSettings::default(),
            webauthn: WebAuthnSettings::default(),
            database: DatabaseSettings::default(),
        }
    }
}

/// Server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: None,
        }
    }
}

/// WebAuthn settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSettings {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub timeout: u64,
}

impl Default for WebAuthnSettings {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "FIDO2 WebAuthn Server".to_string(),
            origin: "http://localhost:8080".to_string(),
            timeout: 60000,
        }
    }
}

/// Database settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

impl Default for DatabaseSettings {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/fido2_test".to_string(),
            max_connections: 10,
            min_connections: 1,
        }
    }
}