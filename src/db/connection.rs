//! Database connection management

use crate::config::DatabaseConfig;
use crate::error::{AppError, Result};
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use std::time::Duration;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Create database connection pool
pub fn create_pool(config: &DatabaseConfig) -> Result<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(&config.url);
    
    let mut builder = Pool::builder()
        .max_size(config.max_connections)
        .connection_timeout(config.connection_timeout())
        .test_on_check_out(true);

    if let Some(min_idle) = config.min_idle {
        builder = builder.min_idle(Some(min_idle));
    }

    if let Some(idle_timeout) = config.idle_timeout() {
        builder = builder.idle_timeout(Some(idle_timeout));
    }

    if let Some(max_lifetime) = config.max_lifetime() {
        builder = builder.max_lifetime(Some(max_lifetime));
    }

    builder
        .build(manager)
        .map_err(|e| AppError::Database(diesel::result::ConnectionError::BadConnection(e.to_string())))
}

/// Run database migrations
pub fn run_migrations(pool: &DbPool) -> Result<()> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

    let mut conn = pool
        .get()
        .map_err(|e| AppError::Database(diesel::result::ConnectionError::BadConnection(e.to_string())))?;

    conn.run_pending_migrations(MIGRATIONS)
        .map(|_| ())
        .map_err(|e| AppError::Database(diesel::result::ConnectionError::BadConnection(e.to_string())))
}