//! Database repository traits and implementations

use async_trait::async_trait;
use diesel::prelude::*;
use std::sync::Arc;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use crate::error::{AppError, Result};
use crate::db::models::*;
use crate::db::DbPool;

/// Type alias for database connection pool
pub type Pool = Arc<DbPool>;

/// Repository trait for user operations
#[async_trait::async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: NewUser) -> Result<User>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>>;
    async fn update_user(&self, user_id: &Uuid, user: NewUser) -> Result<User>;
    async fn delete_user(&self, user_id: &Uuid) -> Result<bool>;
}

/// Repository trait for credential operations
#[async_trait::async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, credential: NewCredential) -> Result<Credential>;
    async fn get_credential_by_id(&self, credential_id: &str) -> Result<Option<Credential>>;
    async fn get_credentials_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
    async fn update_sign_count(&self, credential_id: &str, sign_count: i32) -> Result<bool>;
    async fn update_last_used(&self, credential_id: &str) -> Result<bool>;
    async fn delete_credential(&self, credential_id: &str) -> Result<bool>;
}

/// Repository trait for challenge operations
#[async_trait::async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn create_challenge(&self, challenge: NewChallenge) -> Result<Challenge>;
    async fn get_challenge_by_value(&self, challenge: &str) -> Result<Option<Challenge>>;
    async fn consume_challenge(&self, challenge: &str) -> Result<Option<Challenge>>;
    async fn cleanup_expired_challenges(&self) -> Result<usize>;
}

/// PostgreSQL implementation of UserRepository
pub struct PostgresUserRepository {
    pool: Pool,
}

impl PostgresUserRepository {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(&self, user: NewUser) -> Result<crate::db::models::User> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let user: crate::db::models::User = diesel::insert_into(crate::db::schema::users::table)
            .values(&user)
            .get_result(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))?;

        Ok(user)
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let user = crate::db::schema::users::table
            .filter(crate::db::schema::users::username.eq(username))
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get user: {}", e)))?;

        Ok(user)
    }

    async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let user = crate::db::schema::users::table
            .filter(crate::db::schema::users::id.eq(user_id))
            .first::<User>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get user: {}", e)))?;

        Ok(user)
    }

    async fn update_user(&self, user_id: &Uuid, user: NewUser) -> Result<User> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let user = diesel::update(crate::db::schema::users::table.filter(crate::db::schema::users::id.eq(user_id)))
            .set((
                crate::db::schema::users::username.eq(user.username),
                crate::db::schema::users::display_name.eq(user.display_name),
            ))
            .get_result::<User>(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to update user: {}", e)))?;

        Ok(user)
    }

    async fn delete_user(&self, user_id: &Uuid) -> Result<bool> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let rows_affected = diesel::delete(crate::db::schema::users::table.filter(crate::db::schema::users::id.eq(user_id)))
            .execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete user: {}", e)))?;

        Ok(rows_affected > 0)
    }
}

/// PostgreSQL implementation of CredentialRepository
pub struct PostgresCredentialRepository {
    pool: Pool,
}

impl PostgresCredentialRepository {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn create_credential(&self, credential: NewCredential) -> Result<Credential> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let credential: Credential = diesel::insert_into(crate::db::schema::credentials::table)
            .values(&credential)
            .get_result(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create credential: {}", e)))?;

        Ok(credential)
    }

    async fn get_credential_by_id(&self, credential_id: &str) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let credential = crate::db::schema::credentials::table
            .filter(crate::db::schema::credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get credential: {}", e)))?;

        Ok(credential)
    }

    async fn get_credentials_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let credentials = crate::db::schema::credentials::table
            .filter(crate::db::schema::credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to get credentials: {}", e)))?;

        Ok(credentials)
    }

    async fn update_sign_count(&self, credential_id: &str, sign_count: i32) -> Result<bool> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let rows_affected = diesel::update(
            crate::db::schema::credentials::table
                .filter(crate::db::schema::credentials::credential_id.eq(credential_id))
        )
        .set((
            crate::db::schema::credentials::sign_count.eq(sign_count),
            crate::db::schema::credentials::last_used_at.eq(Utc::now()),
        ))
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(format!("Failed to update sign count: {}", e)))?;

        Ok(rows_affected > 0)
    }

    async fn update_last_used(&self, credential_id: &str) -> Result<bool> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let rows_affected = diesel::update(
            crate::db::schema::credentials::table
                .filter(crate::db::schema::credentials::credential_id.eq(credential_id))
        )
        .set(crate::db::schema::credentials::last_used_at.eq(Utc::now()))
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(format!("Failed to update last used: {}", e)))?;

        Ok(rows_affected > 0)
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<bool> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let rows_affected = diesel::delete(
            crate::db::schema::credentials::table
                .filter(crate::db::schema::credentials::credential_id.eq(credential_id))
        )
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(format!("Failed to delete credential: {}", e)))?;

        Ok(rows_affected > 0)
    }
}

/// PostgreSQL implementation of ChallengeRepository
pub struct PostgresChallengeRepository {
    pool: Pool,
}

impl PostgresChallengeRepository {
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl ChallengeRepository for PostgresChallengeRepository {
    async fn create_challenge(&self, challenge: NewChallenge) -> Result<Challenge> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let challenge: Challenge = diesel::insert_into(crate::db::schema::challenges::table)
            .values(&challenge)
            .get_result(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create challenge: {}", e)))?;

        Ok(challenge)
    }

    async fn get_challenge_by_value(&self, challenge: &str) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let challenge = crate::db::schema::challenges::table
            .filter(crate::db::schema::challenges::challenge.eq(challenge))
            .first::<Challenge>(&mut conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to get challenge: {}", e)))?;

        Ok(challenge)
    }

    async fn consume_challenge(&self, challenge: &str) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            let challenge = crate::db::schema::challenges::table
                .filter(crate::db::schema::challenges::challenge.eq(challenge))
                .first::<Challenge>(conn)
                .optional()?;

            if challenge.is_some() {
                diesel::delete(
                    crate::db::schema::challenges::table
                        .filter(crate::db::schema::challenges::challenge.eq(challenge))
                )
                .execute(conn)?;
            }

            Ok(challenge)
        })
        .map_err(|e| AppError::DatabaseError(format!("Failed to consume challenge: {}", e)))
    }

    async fn cleanup_expired_challenges(&self) -> Result<usize> {
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;

        let rows_affected = diesel::delete(
            crate::db::schema::challenges::table
                .filter(crate::db::schema::challenges::expires_at.lt(Utc::now()))
        )
        .execute(&mut conn)
        .map_err(|e| AppError::DatabaseError(format!("Failed to cleanup challenges: {}", e)))?;

        Ok(rows_affected)
    }
}