//! Database connection management

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::env;

pub type PgPool = Pool<ConnectionManager<PgConnection>>;
pub type PgPooledConnection = PooledConnection<ConnectionManager<PgConnection>>;

/// Create a new database connection pool
pub fn create_pool(database_url: &str) -> crate::error::Result<PgPool> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    let pool = Pool::builder()
        .max_size(15)
        .build(manager)
        .map_err(|e| crate::error::AppError::DatabaseConnection(e))?;
    
    Ok(pool)
}

/// Get database URL from environment or use default
pub fn get_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "postgres://localhost/fido_server".to_string())
}

/// Run database migrations
pub fn run_migrations(pool: &PgPool) -> crate::error::Result<()> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    
    let mut conn = pool.get()
        .map_err(|e| crate::error::AppError::DatabaseConnection(e))?;
    
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|e| crate::error::AppError::Database(diesel::result::Error::DatabaseError(
            diesel::result::DatabaseErrorKind::Unknown,
            Box::new(e.to_string())
        )))?;
    
    Ok(())
}