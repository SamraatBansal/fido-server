use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub server: ServerSettings,
    pub database: DatabaseSettings,
    pub webauthn: WebAuthnSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSettings {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSettings {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                host: "localhost".to_string(),
                port: 8080,
            },
            database: DatabaseSettings {
                url: std::env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgresql://localhost/fido_server".to_string()),
                max_connections: 10,
            },
            webauthn: WebAuthnSettings {
                rp_id: "localhost".to_string(),
                rp_name: "Example Corporation".to_string(),
                origin: "http://localhost:8080".to_string(),
            },
        }
    }
}

impl Settings {
    pub fn load() -> crate::Result<Self> {
        let settings = std::env::var("DATABASE_URL").map(|url| Settings {
            database: DatabaseSettings {
                url,
                max_connections: 10,
            },
            ..Default::default()
        }).unwrap_or_default();
        
        Ok(settings)
    }
}