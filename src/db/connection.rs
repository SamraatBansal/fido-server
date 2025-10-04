//! Database connection management

use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::env;
use crate::error::{AppError, Result};

/// Type alias for database connection pool
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Type alias for pooled connection
pub type PooledDb = PooledConnection<ConnectionManager<PgConnection>>;

/// Database connection manager
pub struct DbManager {
    pool: DbPool,
}

impl DbManager {
    /// Create a new database connection pool
    pub fn new(database_url: &str, max_pool_size: u32) -> Result<Self> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        
        let pool = Pool::builder()
            .max_size(max_pool_size)
            .build(manager)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create connection pool: {}", e)))?;

        // Run migrations
        Self::run_migrations(&pool)?;

        Ok(Self { pool })
    }

    /// Get a connection from the pool
    pub fn get_connection(&self) -> Result<PooledDb> {
        self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {}", e)))
    }

    /// Run database migrations
    fn run_migrations(pool: &DbPool) -> Result<()> {
        let mut conn = pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get connection for migrations: {}", e)))?;

        diesel_migrations::embed_migrations!("migrations");
        
        diesel_migrations::run_pending_migrations(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to run migrations: {}", e)))?;

        Ok(())
    }

    /// Get pool statistics
    pub fn pool_state(&self) -> r2d2::State {
        self.pool.state()
    }
}

/// Initialize database connection from environment
pub fn init_database() -> Result<DbManager> {
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/fido_server".to_string());
    
    let max_pool_size = env::var("DB_MAX_POOL_SIZE")
        .unwrap_or_else(|_| "10".to_string())
        .parse()
        .unwrap_or(10);

    DbManager::new(&database_url, max_pool_size)
}