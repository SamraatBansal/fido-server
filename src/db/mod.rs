use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::env;

pub type Pool = r2d2::Pool<ConnectionManager<SqliteConnection>>;
pub type PooledConnection = r2d2::PooledConnection<ConnectionManager<SqliteConnection>>;

pub fn establish_connection_pool() -> Result<Pool, anyhow::Error> {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "fido_server.db".to_string());
    
    let manager = ConnectionManager::<SqliteConnection>::new(database_url);
    let pool = r2d2::Pool::builder()
        .max_size(15)
        .build(manager)?;
    
    Ok(pool)
}

pub fn run_migrations(_pool: &Pool) -> Result<(), anyhow::Error> {
    // For now, we'll skip automatic migrations and assume the database is set up
    // In production, you would want to run migrations here
    println!("Database migrations skipped - please run them manually");
    
    Ok(())
}