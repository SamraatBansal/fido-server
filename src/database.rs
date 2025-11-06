use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

pub type DbPool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type DbConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

pub fn establish_connection_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:password@localhost/fido2_webauthn".to_string());
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.")
}

pub fn run_migrations(pool: &DbPool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
    
    const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");
    let mut conn = pool.get()?;
    conn.run_pending_migrations(MIGRATIONS)?;
    Ok(())
}