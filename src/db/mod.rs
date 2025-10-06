//! Database connection and pool management

use crate::config::DatabaseConfig;
use crate::error::{AppError, Result};
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use std::time::Duration;

pub mod models;
pub mod connection;

// Embed migrations
pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations");

/// Database connection pool type
pub type DbPool = Pool<ConnectionManager<PgConnection>>;

/// Database connection wrapper
pub struct DbConnection {
    pool: DbPool,
}

impl DbConnection {
    /// Create new database connection pool
    pub fn new(config: &DatabaseConfig) -> Result<Self> {
        let manager = ConnectionManager::<PgConnection>::new(&config.url);
        
        let pool = Pool::builder()
            .max_size(config.max_connections)
            .min_idle(Some(config.min_connections))
            .connection_timeout(Duration::from_secs(config.connection_timeout))
            .idle_timeout(config.idle_timeout.map(Duration::from_secs))
            .build(manager)
            .map_err(|e| AppError::Database(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(format!("Failed to create connection pool: {}", e)),
            )))?;

        Ok(Self { pool })
    }

    /// Get connection from pool
    pub fn get(&self) -> Result<PooledConnection<ConnectionManager<PgConnection>>> {
        self.pool.get().map_err(|e| {
            AppError::Database(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UnableToSendCommand,
                Box::new(format!("Failed to get connection from pool: {}", e)),
            ))
        })
    }

    /// Run database migrations
    pub fn run_migrations(&self) -> Result<()> {
        let mut conn = self.get()?;
        
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| AppError::Database(diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::MigrationError,
                Box::new(format!("Failed to run migrations: {}", e)),
            )))?;

        Ok(())
    }

    /// Test database connection
    pub fn test_connection(&self) -> Result<()> {
        let mut conn = self.get()?;
        
        diesel::sql_query("SELECT 1")
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    /// Get pool state for monitoring
    pub fn pool_state(&self) -> PoolState {
        let state = self.pool.state();
        PoolState {
            connections: state.connections,
            idle_connections: state.idle_connections,
        }
    }
}

/// Pool state information
#[derive(Debug, Clone)]
pub struct PoolState {
    /// Total number of connections
    pub connections: u32,
    /// Number of idle connections
    pub idle_connections: u32,
}

/// Database transaction helper
pub struct Transaction<'a> {
    conn: PooledConnection<ConnectionManager<PgConnection>>,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a> Transaction<'a> {
    /// Begin new transaction
    pub fn begin(pool: &'a DbConnection) -> Result<Self> {
        let conn = pool.get()?;
        conn.begin_transaction().map_err(|e| AppError::Database(e))?;
        
        Ok(Self {
            conn,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Get connection reference
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.conn
    }

    /// Commit transaction
    pub fn commit(self) -> Result<()> {
        self.conn.commit_transaction().map_err(|e| AppError::Database(e))?;
        Ok(())
    }

    /// Rollback transaction
    pub fn rollback(self) -> Result<()> {
        self.conn.rollback_transaction().map_err(|e| AppError::Database(e))?;
        Ok(())
    }
}

impl<'a> Drop for Transaction<'a> {
    fn drop(&mut self) {
        // Auto-rollback if not committed
        let _ = self.conn.rollback_transaction();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_state() {
        let state = PoolState {
            connections: 10,
            idle_connections: 5,
        };
        assert_eq!(state.connections, 10);
        assert_eq!(state.idle_connections, 5);
    }
}