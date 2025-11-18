//! Database connection management

use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;
use std::time::Duration;

use crate::{AppError, Result};

/// Type alias for database connection pool
pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;

/// Establish database connection pool
///
/// # Arguments
///
/// * `database_url` - PostgreSQL database URL
/// * `max_pool_size` - Maximum pool size
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn establish_connection(database_url: &str, max_pool_size: u32) -> Result<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    r2d2::Pool::builder()
        .max_size(max_pool_size)
        .min_idle(Some(5))
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Some(Duration::from_secs(600))) // 10 minutes
        .max_lifetime(Some(Duration::from_secs(1800))) // 30 minutes
        .build(manager)
        .map_err(|e| AppError::DatabaseError(format!("Failed to establish connection pool: {e}")))
}
