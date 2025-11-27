//! Database connection management

use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use std::time::Duration;
use crate::config::settings::DatabaseSettings;
use crate::error::AppError;

/// Type alias for database connection pool
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

/// Establish database connection pool
///
/// # Arguments
///
/// * `database_url` - PostgreSQL database URL
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn establish_connection(database_url: &str) -> Result<DbPool, r2d2::PoolError> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder().build(manager)
}

/// Create database connection pool with configuration
///
/// # Arguments
///
/// * `config` - Database configuration settings
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn create_pool(config: &DatabaseSettings) -> Result<DbPool, AppError> {
    let manager = ConnectionManager::<PgConnection>::new(&config.url);
    
    let pool = r2d2::Pool::builder()
        .max_size(config.max_pool_size)
        .connection_timeout(Duration::from_secs(config.connection_timeout))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout)))
        .test_on_check_out(true)
        .build(manager)
        .map_err(|e| AppError::DatabaseError(format!("Failed to create connection pool: {:?}", e)))?;
    
    // Test the connection
    test_connection(&pool)?;
    
    log::info!("Database connection pool created with {} max connections", config.max_pool_size);
    Ok(pool)
}

/// Test database connectivity
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Errors
///
/// Returns an error if database connection test fails
pub fn test_connection(pool: &DbPool) -> Result<(), AppError> {
    use diesel::prelude::*;
    use diesel::sql_query;
    
    let mut conn = pool.get()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get connection from pool: {:?}", e)))?;
    
    sql_query("SELECT 1")
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(format!("Database connectivity test failed: {:?}", e)))?;
    
    Ok(())
}
