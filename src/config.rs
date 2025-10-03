use serde::Deserialize;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub webhook_url: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let database_url = env::var("DATABASE_URL")
            .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable must be set"))?;
        
        let port = env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|_| anyhow::anyhow!("PORT must be a valid number"))?;

        let rp_id = env::var("RP_ID")
            .unwrap_or_else(|_| "localhost".to_string());
        
        let rp_name = env::var("RP_NAME")
            .unwrap_or_else(|_| "FIDO2 Server".to_string());
        
        let rp_origin = env::var("RP_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:8080".to_string());

        let webhook_url = env::var("WEBHOOK_URL").ok();

        Ok(Config {
            database_url,
            port,
            rp_id,
            rp_name,
            rp_origin,
            webhook_url,
        })
    }
}