//! Application state management

use std::sync::Arc;
use crate::config::Settings;
use crate::db::DbPool;
use crate::redis::RedisPool;
use crate::error::AppError;

/// Thread-safe application state shared across Actix workers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db_pool: Arc<DbPool>,
    /// Redis connection pool
    pub redis_pool: Arc<RedisPool>,
    /// Application configuration
    pub config: Arc<Settings>,
}

impl AppState {
    /// Create new application state
    ///
    /// # Arguments
    ///
    /// * `config` - Application configuration
    ///
    /// # Errors
    ///
    /// Returns an error if database or Redis connections cannot be established
    pub async fn new(config: Settings) -> Result<Self, AppError> {
        log::info!("Initializing application state...");
        
        // Validate configuration
        config.validate()
            .map_err(|e| AppError::ConfigError(e))?;
        
        // Create database connection pool
        log::info!("Creating database connection pool...");
        let db_pool = crate::db::create_pool(&config.database)?;
        
        // Create Redis connection pool
        log::info!("Creating Redis connection pool...");
        let redis_pool = crate::redis::create_pool(&config.redis)?;
        
        // Test Redis connectivity
        crate::redis::test_connection(&redis_pool).await?;
        log::info!("Redis connectivity test passed");
        
        let state = Self {
            db_pool: Arc::new(db_pool),
            redis_pool: Arc::new(redis_pool),
            config: Arc::new(config),
        };
        
        log::info!("Application state initialized successfully");
        Ok(state)
    }
    
    /// Get database connection pool
    pub fn db_pool(&self) -> Arc<DbPool> {
        Arc::clone(&self.db_pool)
    }
    
    /// Get Redis connection pool
    pub fn redis_pool(&self) -> Arc<RedisPool> {
        Arc::clone(&self.redis_pool)
    }
    
    /// Get application configuration
    pub fn config(&self) -> Arc<Settings> {
        Arc::clone(&self.config)
    }
}