//! Database connection management

use crate::config::DatabaseSettings;
use crate::error::{AppError, Result};
use diesel::r2d2::{self, ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use std::sync::Arc;
use std::time::Duration;

/// Type alias for database connection pool
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Type alias for pooled database connection
pub type DbConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Thread-safe database pool wrapper
pub type SharedDbPool = Arc<DbPool>;

/// Establish database connection pool with proper configuration
///
/// # Arguments
///
/// * `config` - Database configuration settings
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn establish_connection_pool(config: &DatabaseSettings) -> Result<DbPool> {
    // Validate database URL format
    if !config.url.starts_with("postgres://") && !config.url.starts_with("postgresql://") {
        return Err(AppError::ConfigError(
            "Database URL must start with postgres:// or postgresql://".to_string(),
        ));
    }

    let manager = ConnectionManager::<PgConnection>::new(&config.url);
    
    let pool = Pool::builder()
        .max_size(config.max_pool_size)
        .connection_timeout(Duration::from_secs(config.timeout_seconds))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout_seconds)))
        .test_on_check_out(true)
        .build(manager)
        .map_err(|e| {
            log::error!("Failed to create database pool: {}", e);
            AppError::DatabaseError("Failed to establish database connection pool".to_string())
        })?;

    // Test the connection
    test_connection(&pool)?;
    
    log::info!("Database connection pool established successfully");
    Ok(pool)
}

/// Test database connection health
///
/// # Arguments
///
/// * `pool` - Database connection pool to test
///
/// # Errors
///
/// Returns an error if connection test fails
pub fn test_connection(pool: &DbPool) -> Result<()> {
    use diesel::sql_query;
    use diesel::RunQueryDsl;

    let mut conn = pool.get().map_err(|e| {
        log::error!("Failed to get database connection: {}", e);
        AppError::DatabaseError("Database connection unavailable".to_string())
    })?;

    sql_query("SELECT 1")
        .execute(&mut conn)
        .map_err(|e| {
            log::error!("Database health check failed: {}", e);
            AppError::DatabaseError("Database health check failed".to_string())
        })?;

    Ok(())
}

/// Get database connection from pool with proper error handling
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Errors
///
/// Returns an error if connection cannot be acquired
pub fn get_connection(pool: &DbPool) -> Result<DbConnection> {
    pool.get().map_err(|e| {
        log::error!("Failed to acquire database connection: {}", e);
        AppError::DatabaseError("Failed to acquire database connection".to_string())
    })
}
