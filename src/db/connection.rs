//! Database connection management

use sqlx::{PgPool, postgres::PgPoolOptions};
use std::time::Duration;

/// Database connection pool
pub type DbPool = PgPool;

/// Create database connection pool
pub async fn create_pool(database_url: &str) -> Result<DbPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await
}

/// Initialize database with migrations
pub async fn init_database(pool: &DbPool) -> Result<(), sqlx::Error> {
    // Run migrations - disabled for now since migrations directory doesn't exist
    // sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool() {
        // This test would require a test database
        // For now, we'll just test that the function compiles
        let _pool = create_pool("postgresql://localhost/test").await;
        // In real tests, you'd set up a test database
    }
}