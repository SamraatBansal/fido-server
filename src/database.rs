use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

pub type DbConnection = PgConnection;
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

pub fn establish_connection_pool() -> Result<DbPool, Box<dyn std::error::Error>> {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost:5432/fido2_webauthn".to_string());
    
    tracing::info!("Connecting to database: {}", 
        if database_url.contains("password") { 
            database_url.replace("password", "***") 
        } else { 
            database_url.clone() 
        }
    );
    
    // Clean the URL to remove any problematic query parameters
    let clean_url = if database_url.contains('?') {
        let parts: Vec<&str> = database_url.split('?').collect();
        let base_url = parts[0];
        
        // Only allow specific valid PostgreSQL parameters
        if parts.len() > 1 {
            let params = parts[1];
            let valid_params: Vec<&str> = params
                .split('&')
                .filter(|param| {
                    param.starts_with("sslmode=") || 
                    param.starts_with("application_name=") ||
                    param.starts_with("connect_timeout=")
                })
                .collect();
            
            if valid_params.is_empty() {
                base_url.to_string()
            } else {
                format!("{}?{}", base_url, valid_params.join("&"))
            }
        } else {
            database_url
        }
    } else {
        database_url
    };
    
    let manager = ConnectionManager::<PgConnection>::new(clean_url);
    let pool = r2d2::Pool::builder()
        .max_size(10)
        .connection_timeout(std::time::Duration::from_secs(5))
        .build(manager)?;
    
    // Test connection
    let _conn = pool.get()?;
    tracing::info!("PostgreSQL database connection established successfully");
    Ok(pool)
}

pub fn run_migrations(pool: &DbPool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    let mut conn = pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}