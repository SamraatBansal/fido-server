//! Redis connection management

use deadpool_redis::{Config, Pool, Runtime};
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, RedisResult};
use std::time::Duration;
use crate::config::RedisSettings;
use crate::error::AppError;

/// Type alias for Redis connection pool
pub type RedisPool = Pool;

/// Create Redis connection pool with configuration
///
/// # Arguments
///
/// * `config` - Redis configuration settings
///
/// # Errors
///
/// Returns an error if the connection pool cannot be established
pub fn create_pool(config: &RedisSettings) -> Result<RedisPool, AppError> {
    let cfg = Config::from_url(&config.url);
    
    let pool = cfg
        .builder()
        .max_size(config.max_pool_size)
        .timeouts(deadpool_redis::Timeouts {
            wait: Some(Duration::from_secs(config.connection_timeout)),
            create: Some(Duration::from_secs(config.connection_timeout)),
            recycle: Some(Duration::from_secs(3)),
        })
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| AppError::RedisError(format!("Failed to create Redis pool: {:?}", e)))?;
    
    log::info!("Redis connection pool created with {} max connections", config.max_pool_size);
    Ok(pool)
}

/// Test Redis connectivity
///
/// # Arguments
///
/// * `pool` - Redis connection pool
///
/// # Errors
///
/// Returns an error if Redis connection test fails
pub async fn test_connection(pool: &RedisPool) -> Result<(), AppError> {
    let mut conn = pool.get().await
        .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection from pool: {:?}", e)))?;
    
    let result: RedisResult<String> = redis::cmd("PING").query_async(&mut conn).await;
    
    result
        .map_err(|e| AppError::RedisError(format!("Redis connectivity test failed: {:?}", e)))?;
    
    Ok(())
}

/// Store session data in Redis with TTL
///
/// # Arguments
///
/// * `pool` - Redis connection pool
/// * `key` - Session key
/// * `data` - Session data (JSON string)
/// * `ttl_seconds` - Time to live in seconds
///
/// # Errors
///
/// Returns an error if Redis operation fails
pub async fn store_session_data(
    pool: &RedisPool,
    key: &str,
    data: &str,
    ttl_seconds: u64,
) -> Result<(), AppError> {
    let mut conn = pool.get().await
        .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {:?}", e)))?;
    
    conn.set_ex(key, data, ttl_seconds as usize).await
        .map_err(|e| AppError::RedisError(format!("Failed to store session data: {:?}", e)))?;
    
    Ok(())
}

/// Retrieve session data from Redis
///
/// # Arguments
///
/// * `pool` - Redis connection pool
/// * `key` - Session key
///
/// # Errors
///
/// Returns an error if Redis operation fails or key not found
pub async fn get_session_data(
    pool: &RedisPool,
    key: &str,
) -> Result<String, AppError> {
    let mut conn = pool.get().await
        .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {:?}", e)))?;
    
    let result: Option<String> = conn.get(key).await
        .map_err(|e| AppError::RedisError(format!("Failed to retrieve session data: {:?}", e)))?;
    
    result.ok_or_else(|| AppError::NotFound("Session not found".to_string()))
}

/// Delete session data from Redis
///
/// # Arguments
///
/// * `pool` - Redis connection pool
/// * `key` - Session key
///
/// # Errors
///
/// Returns an error if Redis operation fails
pub async fn delete_session_data(
    pool: &RedisPool,
    key: &str,
) -> Result<(), AppError> {
    let mut conn = pool.get().await
        .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {:?}", e)))?;
    
    conn.del(key).await
        .map_err(|e| AppError::RedisError(format!("Failed to delete session data: {:?}", e)))?;
    
    Ok(())
}