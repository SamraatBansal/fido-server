//! Database models and connection management

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::result::Error as DieselError;
use std::env;
use uuid::Uuid;
use chrono::{DateTime, Utc};

pub mod models;
pub mod schema;

/// Database connection pool type
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Database connection
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Initialize database connection pool
pub fn init_pool(database_url: &str, max_connections: u32) -> Result<DbPool, crate::error::AppError> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .max_size(max_connections)
        .build(manager)
        .map_err(|e| crate::error::AppError::DatabaseConnection(e.to_string()))?;
    
    Ok(pool)
}

/// Get database URL from environment or use default
pub fn get_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/fido_server".to_string())
}

/// Run database migrations
pub fn run_migrations(pool: &DbPool) -> Result<(), crate::error::AppError> {
    let mut conn = pool.get().map_err(|e| crate::error::AppError::DatabaseConnection(e.to_string()))?;
    // For now, skip migrations until we fix the diesel_migrations issue
    // diesel_migrations::embed_migrations!("migrations");
    // diesel_migrations::run_pending_migrations(&mut conn)?;
    Ok(())
}