use crate::db::models::{NewUser, User};
use crate::error::{AppError, Result};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone)]
pub struct UserRepository {
    pool: PgPool,
}

impl UserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_user(&self, new_user: NewUser) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, display_name, user_id)
            VALUES ($1, $2, $3)
            RETURNING id, username, display_name, user_id, created_at, updated_at, status
            "#,
            new_user.username,
            new_user.display_name,
            new_user.user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, display_name, user_id, created_at, updated_at, status
            FROM users 
            WHERE username = $1 AND status = 'active'
            "#,
            username
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, display_name, user_id, created_at, updated_at, status
            FROM users 
            WHERE id = $1 AND status = 'active'
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn get_user_by_webauthn_user_id(&self, webauthn_user_id: &[u8]) -> Result<Option<User>> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT id, username, display_name, user_id, created_at, updated_at, status
            FROM users 
            WHERE user_id = $1 AND status = 'active'
            "#,
            webauthn_user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn user_exists(&self, username: &str) -> Result<bool> {
        let count = sqlx::query_scalar!(
            "SELECT COUNT(*) FROM users WHERE username = $1 AND status = 'active'",
            username
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(count.unwrap_or(0) > 0)
    }

    pub async fn update_user_display_name(&self, user_id: Uuid, display_name: &str) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users 
            SET display_name = $2, updated_at = NOW()
            WHERE id = $1 AND status = 'active'
            RETURNING id, username, display_name, user_id, created_at, updated_at, status
            "#,
            user_id,
            display_name
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    pub async fn deactivate_user(&self, user_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE users SET status = 'inactive', updated_at = NOW() WHERE id = $1",
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}