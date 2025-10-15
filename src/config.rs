#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub database_url: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: std::env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse()
                .expect("PORT must be a valid number"),
            rp_id: std::env::var("RP_ID").unwrap_or_else(|_| "localhost".to_string()),
            rp_name: std::env::var("RP_NAME").unwrap_or_else(|_| "FIDO2 Test Server".to_string()),
            rp_origin: std::env::var("RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string()),
            database_url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://user:pass@localhost/fido2_test".to_string()),
        }
    }

    pub fn for_testing() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 0, // Let the OS choose a free port
            rp_id: "localhost".to_string(),
            rp_name: "Test RP".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
            database_url: "postgres://test:test@localhost/fido2_test".to_string(),
        }
    }
}