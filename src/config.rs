use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    pub server_addr: SocketAddr,
    pub database_url: String,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub webhook_url: Option<String>,
    pub jwt_secret: String,
}

impl Config {
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Config::try_from(&ConfigEnv::default())?)
            .build()?;

        Ok(Config {
            server_addr: settings.get("server_addr")?,
            database_url: settings.get("database_url")?,
            rp_id: settings.get("rp_id")?,
            rp_name: settings.get("rp_name")?,
            rp_origin: settings.get("rp_origin")?,
            webhook_url: settings.get("webhook_url").ok(),
            jwt_secret: settings.get("jwt_secret")?,
        })
    }
}

#[derive(Debug, Deserialize)]
struct ConfigEnv {
    server_addr: SocketAddr,
    database_url: String,
    rp_id: String,
    rp_name: String,
    rp_origin: String,
    webhook_url: Option<String>,
    jwt_secret: String,
}

impl Default for ConfigEnv {
    fn default() -> Self {
        ConfigEnv {
            server_addr: "0.0.0.0:8080".parse().unwrap(),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://localhost/fido_server".to_string()),
            rp_id: std::env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_name: std::env::var("RP_NAME")
                .unwrap_or_else(|_| "FIDO Server".to_string()),
            rp_origin: std::env::var("RP_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:8080".to_string()),
            webhook_url: std::env::var("WEBHOOK_URL").ok(),
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "your-secret-key-change-in-production".to_string()),
        }
    }
}