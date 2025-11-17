use crate::config::DatabaseSettings;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::time::Duration;

pub type DbConnection = PgConnection;
pub type DbPool = Pool<ConnectionManager<DbConnection>>;
pub type PooledDbConnection = PooledConnection<ConnectionManager<DbConnection>>;

pub fn create_pool(settings: &DatabaseSettings) -> crate::Result<DbPool> {
    let manager = ConnectionManager::<PgConnection>::new(&settings.url);
    
    let pool = Pool::builder()
        .max_size(settings.max_connections)
        .min_idle(Some(2))
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Some(Duration::from_secs(600)))
        .build(manager)?;
        
    Ok(pool)
}