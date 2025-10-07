use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel::pg::PgConnection;
use std::env;

pub type PgPool = Pool<ConnectionManager<PgConnection>>;
pub type PgPooledConn = PooledConnection<ConnectionManager<PgConnection>>;

pub fn establish_connection_pool() -> Result<PgPool, diesel::result::ConnectionError> {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    Pool::builder()
        .max_size(15)
        .build(manager)
}

pub fn get_connection(pool: &PgPool) -> Result<PgPooledConn, diesel::r2d2::Error> {
    pool.get()
}