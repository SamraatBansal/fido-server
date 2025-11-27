//! Application state management

use crate::config::Settings;
use crate::db::{establish_connection_pool, SharedDbPool, get_connection, test_connection, DbConnection};
use crate::error::{AppError, Result};
use crate::redis::{establish_redis_pool, SharedRedisPool};
use std::sync::Arc;

/// Application state containing shared resources
///
/// All fields are wrapped in Arc for efficient cloning across Actix workers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db_pool: SharedDbPool,
    
    /// Redis connection pool
    pub redis_pool: SharedRedisPool,
    
    /// Application configuration
    pub config: Arc<Settings>,
}

impl AppState {
    /// Create new application state from configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Application configuration settings
    ///
    /// # Errors
    ///
    /// Returns an error if connection pools cannot be established
    pub async fn new(config: Settings) -> Result<Self> {
        log::info!("Initializing application state...");

        // Establish database connection pool
        log::info!("Establishing database connection pool...");
        let db_pool = establish_connection_pool(&config.database)?;
        let shared_db_pool = Arc::new(db_pool);

        // Establish Redis connection pool
        log::info!("Establishing Redis connection pool...");
        let redis_pool = establish_redis_pool(&config.redis)?;
        let shared_redis_pool = Arc::new(redis_pool);

        // Test Redis connection
        crate::redis::test_redis_connection(&shared_redis_pool).await?;

        let app_state = Self {
            db_pool: shared_db_pool,
            redis_pool: shared_redis_pool,
            config: Arc::new(config),
        };

        log::info!("Application state initialized successfully");
        Ok(app_state)
    }

    /// Get database connection from pool
    ///
    /// # Errors
    ///
    /// Returns an error if connection cannot be acquired
    pub fn get_db_connection(&self) -> Result<DbConnection> {
        get_connection(&self.db_pool)
    }

    /// Get Redis connection from pool
    ///
    /// # Errors
    ///
    /// Returns an error if connection cannot be acquired
    pub async fn get_redis_connection(&self) -> Result<crate::redis::RedisConnection> {
        crate::redis::get_redis_connection(&self.redis_pool).await
    }

    /// Check health of all connected services
    ///
    /// # Errors
    ///
    /// Returns an error if any service is unhealthy
    pub async fn health_check(&self) -> Result<HealthStatus> {
        let mut status = HealthStatus::default();

        // Check database connection
        match crate::db::test_connection(&self.db_pool) {
            Ok(()) => {
                status.database = ServiceStatus::Connected;
                log::debug!("Database health check: OK");
            }
            Err(e) => {
                status.database = ServiceStatus::Error(e.to_string());
                status.overall_healthy = false;
                log::warn!("Database health check failed: {}", e);
            }
        }

        // Check Redis connection
        match crate::redis::test_redis_connection(&self.redis_pool).await {
            Ok(()) => {
                status.redis = ServiceStatus::Connected;
                log::debug!("Redis health check: OK");
            }
            Err(e) => {
                status.redis = ServiceStatus::Error(e.to_string());
                status.overall_healthy = false;
                log::warn!("Redis health check failed: {}", e);
            }
        }

        if status.overall_healthy {
            log::debug!("Overall health check: OK");
            Ok(status)
        } else {
            log::warn!("Overall health check: FAILED");
            Err(AppError::ServiceUnavailable("One or more services are unavailable".to_string()))
        }
    }
}

/// Health status information
#[derive(Debug, Clone)]
pub struct HealthStatus {
    /// Overall system health
    pub overall_healthy: bool,
    
    /// Database service status
    pub database: ServiceStatus,
    
    /// Redis service status
    pub redis: ServiceStatus,
    
    /// Application version
    pub version: String,
    
    /// Health check timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            overall_healthy: true,
            database: ServiceStatus::Unknown,
            redis: ServiceStatus::Unknown,
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: chrono::Utc::now(),
        }
    }
}

/// Individual service status
#[derive(Debug, Clone)]
pub enum ServiceStatus {
    /// Service is connected and healthy
    Connected,
    
    /// Service has an error
    Error(String),
    
    /// Service status is unknown
    Unknown,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connected => write!(f, "connected"),
            Self::Error(_) => write!(f, "error"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}