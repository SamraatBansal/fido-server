use crate::config::DatabaseConfig;
use crate::error::{AppError, Result};
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::time::Duration;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

pub fn establish_connection(config: &DatabaseConfig) -> Result<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(&config.url);
    
    Pool::builder()
        .max_size(config.max_connections)
        .min_idle(Some(config.min_connections))
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Some(Duration::from_secs(600)))
        .build(manager)
        .map_err(|e| AppError::Internal(format!("Failed to create connection pool: {}", e)))
}

pub fn get_connection(pool: &DbPool) -> Result<DbConnection> {
    pool.get()
        .map_err(|e| AppError::Internal(format!("Failed to get database connection: {}", e)))
}