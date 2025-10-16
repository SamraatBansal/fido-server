//! Database connection management

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::env;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;
pub type DbConn = PooledConnection<ConnectionManager<PgConnection>>;

/// Establish database connection pool
pub fn establish_connection() -> Result<DbPool, diesel::result::ConnectionError> {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .max_size(15)
        .build(manager)
}

/// Get a connection from the pool
pub fn get_connection(pool: &DbPool) -> Result<DbConn, diesel::r2d2::PoolError> {
    pool.get()
}