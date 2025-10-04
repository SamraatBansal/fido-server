//! Database connection management

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::env;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Create database connection pool
pub fn create_pool() -> crate::error::Result<DbPool> {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/fido_server".to_string());
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    Pool::builder()
        .build(manager)
        .map_err(|e| crate::error::AppError::DatabaseError(format!("Failed to create pool: {}", e)))
}