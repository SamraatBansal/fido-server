//! Database connection management

use diesel::r2d2::{self, ConnectionManager, Pool, PooledConnection};
use diesel::PgConnection;
use std::time::Duration;

/// Type alias for database connection pool
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Type alias for pooled connection
pub type PooledDbConn = PooledConnection<ConnectionManager<PgConnection>>;

/// Establish database connection pool with optimized settings
///
/// # Arguments
///
/// * `database_url` - PostgreSQL database URL
/// * `max_pool_size` - Maximum number of connections in the pool
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn establish_connection(database_url: &str, max_pool_size: u32) -> Result<DbPool, r2d2::PoolError> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    Pool::builder()
        .max_size(max_pool_size)
        .min_idle(Some(std::cmp::max(1, max_pool_size / 3)))
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Some(Duration::from_secs(600))) // 10 minutes
        .max_lifetime(Some(Duration::from_secs(1800))) // 30 minutes
        .test_on_check_out(true)
        .build(manager)
}

/// Create a connection pool with default settings
///
/// # Arguments
///
/// * `database_url` - PostgreSQL database URL
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn establish_connection_default(database_url: &str) -> Result<DbPool, r2d2::PoolError> {
    establish_connection(database_url, 15)
}

/// Run database migrations
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Errors
///
/// Returns an error if migrations cannot be run
pub fn run_migrations(pool: &DbPool) -> Result<(), diesel_migrations::RunMigrationsError> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    
    let mut conn = pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)?;
    
    Ok(())
}

/// Health check for database connection
///
/// # Arguments
///
/// * `pool` - Database connection pool
///
/// # Errors
///
/// Returns an error if database is not accessible
pub fn health_check(pool: &DbPool) -> Result<(), diesel::result::Error> {
    use diesel::dsl::sql;
    use diesel::RunQueryDsl;
    
    let mut conn = pool.get()?;
    sql("SELECT 1").execute(&mut conn)?;
    
    Ok(())
}
