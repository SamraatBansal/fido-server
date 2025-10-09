//! Database connection management

use sqlx::PgPool;
use crate::error::AppResult;

/// Type alias for database connection pool
pub type DbPool = PgPool;

/// Establish database connection pool
///
/// # Arguments
///
/// * `database_url` - PostgreSQL database URL
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub async fn establish_connection(database_url: &str) -> AppResult<DbPool> {
    let pool = PgPool::connect(database_url).await?;
    Ok(pool)
}
