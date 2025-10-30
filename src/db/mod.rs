use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

pub type Pool = r2d2::Pool<ConnectionManager<PgConnection>>;
pub type PooledConnection = r2d2::PooledConnection<ConnectionManager<PgConnection>>;

pub fn establish_connection_pool() -> Result<Pool, anyhow::Error> {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/fido_server".to_string());
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .max_size(15)
        .build(manager)?;
    
    Ok(pool)
}

pub fn run_migrations(pool: &Pool) -> Result<(), anyhow::Error> {
    let mut conn = pool.get()?;
    
    // Run migrations using diesel_migrations
    let migration_result = diesel_migrations::run_pending_migrations(&mut conn);
    
    match migration_result {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Migration failed: {}", e)),
    }
}