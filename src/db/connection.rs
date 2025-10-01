//! Database connection management

use diesel::r2d2::{self, ConnectionManager};
use diesel::PgConnection;

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
