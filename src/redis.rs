//! Redis connection management

use crate::config::settings::RedisSettings;
use crate::error::{AppError, Result};
use deadpool_redis::{Config, Connection, Pool, Runtime};
use redis::AsyncCommands;
use std::sync::Arc;
use std::time::Duration;

/// Type alias for Redis connection pool
pub type RedisPool = Pool;

/// Type alias for Redis connection
pub type RedisConnection = Connection;

/// Thread-safe Redis pool wrapper
pub type SharedRedisPool = Arc<RedisPool>;

/// Establish Redis connection pool with proper configuration
///
/// # Arguments
///
/// * `config` - Redis configuration settings
///
/// # Errors
///
/// Returns an error if the Redis pool cannot be established
pub fn establish_redis_pool(config: &RedisSettings) -> Result<RedisPool> {
    // Validate Redis URL format
    if !config.url.starts_with("redis://") && !config.url.starts_with("rediss://") {
        return Err(AppError::ConfigError(
            "Redis URL must start with redis:// or rediss://".to_string(),
        ));
    }

    let cfg = Config::from_url(&config.url);
    
    let pool = cfg
        .builder()
        .map_err(|e| {
            log::error!("Failed to create Redis pool builder: {}", e);
            AppError::RedisError("Failed to configure Redis connection pool".to_string())
        })?
        .max_size(config.max_size as usize)
        .wait_timeout(Some(Duration::from_secs(config.timeout_seconds)))
        .create_timeout(Some(Duration::from_secs(config.timeout_seconds)))
        .recycle_timeout(Some(Duration::from_secs(config.recycle_timeout_seconds)))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| {
            log::error!("Failed to build Redis pool: {}", e);
            AppError::RedisError("Failed to establish Redis connection pool".to_string())
        })?;

    log::info!("Redis connection pool established successfully");
    Ok(pool)
}

/// Test Redis connection health
///
/// # Arguments
///
/// * `pool` - Redis connection pool to test
///
/// # Errors
///
/// Returns an error if connection test fails
pub async fn test_redis_connection(pool: &RedisPool) -> Result<()> {
    let mut conn = get_redis_connection(pool).await?;
    
    // Test with PING command
    let pong: String = conn.ping().await.map_err(|e| {
        log::error!("Redis PING failed: {}", e);
        AppError::RedisError("Redis health check failed".to_string())
    })?;

    if pong != "PONG" {
        return Err(AppError::RedisError("Redis PING returned unexpected response".to_string()));
    }

    Ok(())
}

/// Get Redis connection from pool with proper error handling
///
/// # Arguments
///
/// * `pool` - Redis connection pool
///
/// # Errors
///
/// Returns an error if connection cannot be acquired
pub async fn get_redis_connection(pool: &RedisPool) -> Result<RedisConnection> {
    pool.get().await.map_err(|e| {
        log::error!("Failed to acquire Redis connection: {}", e);
        AppError::RedisError("Failed to acquire Redis connection".to_string())
    })
}

/// Store challenge state in Redis
///
/// # Arguments
///
/// * `pool` - Redis connection pool
/// * `challenge` - Base64URL encoded challenge
/// * `user_id` - User identifier
/// * `origin` - Request origin
/// * `ttl_seconds` - Time to live in seconds
///
/// # Errors
///
/// Returns an error if the operation fails
pub async fn store_challenge_state(
    pool: &RedisPool,
    challenge: &str,
    user_id: &str,
    origin: &str,
    ttl_seconds: u64,
) -> Result<()> {
    let mut conn = get_redis_connection(pool).await?;
    
    let key = format!("auth:challenge:{}", challenge);
    let value = serde_json::json!({
        "user_id": user_id,
        "origin": origin,
        "timestamp": chrono::Utc::now().timestamp()
    });

    conn.set_ex(&key, value.to_string(), ttl_seconds as usize)
        .await
        .map_err(|e| {
            log::error!("Failed to store challenge state: {}", e);
            AppError::RedisError("Failed to store authentication state".to_string())
        })?;

    log::debug!("Stored challenge state for challenge: {}", challenge);
    Ok(())
}

/// Retrieve and remove challenge state from Redis
///
/// # Arguments
///
/// * `pool` - Redis connection pool
/// * `challenge` - Base64URL encoded challenge
///
/// # Returns
///
/// Returns the challenge state data or None if not found
///
/// # Errors
///
/// Returns an error if the operation fails
pub async fn get_and_remove_challenge_state(
    pool: &RedisPool,
    challenge: &str,
) -> Result<Option<serde_json::Value>> {
    let mut conn = get_redis_connection(pool).await?;
    
    let key = format!("auth:challenge:{}", challenge);
    
    // Get the value first
    let value: Option<String> = conn.get(&key).await.map_err(|e| {
        log::error!("Failed to retrieve challenge state: {}", e);
        AppError::RedisError("Failed to retrieve authentication state".to_string())
    })?;

    if let Some(value_str) = value {
        // Delete the key
        let _: () = conn.del(&key).await.map_err(|e| {
            log::error!("Failed to delete challenge state: {}", e);
            AppError::RedisError("Failed to cleanup authentication state".to_string())
        })?;

        // Parse JSON
        let parsed: serde_json::Value = serde_json::from_str(&value_str).map_err(|e| {
            log::error!("Failed to parse challenge state JSON: {}", e);
            AppError::RedisError("Invalid authentication state format".to_string())
        })?;

        log::debug!("Retrieved and removed challenge state for challenge: {}", challenge);
        Ok(Some(parsed))
    } else {
        log::debug!("No challenge state found for challenge: {}", challenge);
        Ok(None)
    }
}