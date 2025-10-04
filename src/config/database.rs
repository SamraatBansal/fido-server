//! Database configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_idle: Option<u32>,
    pub connection_timeout_secs: u64,
    pub idle_timeout_secs: Option<u64>,
    pub max_lifetime_secs: Option<u64>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "postgres://localhost/fido_server".to_string(),
            max_connections: 10,
            min_idle: Some(1),
            connection_timeout_secs: 30,
            idle_timeout_secs: Some(600),
            max_lifetime_secs: Some(1800),
        }
    }
}

impl DatabaseConfig {
    pub fn connection_timeout(&self) -> Duration {
        Duration::from_secs(self.connection_timeout_secs)
    }

    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout_secs.map(Duration::from_secs)
    }

    pub fn max_lifetime(&self) -> Option<Duration> {
        self.max_lifetime_secs.map(Duration::from_secs)
    }
}