//! Database connection pool and utilities

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::sync::Arc;

pub type PgPool = Pool<ConnectionManager<PgConnection>>;
pub type PooledPg = PooledConnection<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct Database {
    pool: Arc<PgPool>,
}

impl Database {
    pub fn new(database_url: &str, max_connections: u32) -> Result<Self, crate::error::AppError> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(max_connections)
            .build(manager)
            .map_err(|e| crate::error::AppError::DatabaseConnection(e.to_string()))?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }

    pub fn get_connection(&self) -> Result<PooledPg, crate::error::AppError> {
        self.pool.get().map_err(|e| crate::error::AppError::DatabaseConnection(e.to_string()))
    }
}