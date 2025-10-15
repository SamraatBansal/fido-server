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
    pub max_pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSettings {
    pub rp_id: String,
    pub rp_name: String,
    pub origin: String,
    pub timeout: Option<u32>,
}

impl Settings {
    pub fn new() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::with_prefix("FIDO2"))
            .set_default("server.host", "127.0.0.1")?
            .set_default("server.port", 8080)?
            .set_default("database.url", "postgres://postgres:postgres@localhost/fido2_test")?
            .set_default("database.max_pool_size", 10)?
            .set_default("webauthn.rp_id", "localhost")?
            .set_default("webauthn.rp_name", "FIDO2 Test Server")?
            .set_default("webauthn.origin", "https://localhost:8080")?
            .set_default("webauthn.timeout", 60000)?
            .build()?;

        settings.try_deserialize()
    }
}