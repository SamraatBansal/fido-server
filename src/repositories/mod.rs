use crate::error::Result;
use crate::models::{User, NewUser, Credential, NewCredential, Challenge, NewChallenge};
use crate::schema::{users, credentials, challenges};
use diesel::prelude::*;
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;
use async_trait::async_trait;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn create_user(&self, user: &NewUser) -> Result<User>;
    async fn find_by_id(&self, id: &str) -> Result<Option<User>>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<Credential>>;
    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    async fn create_credential(&self, credential: &NewCredential) -> Result<Credential>;
    async fn update_sign_count(&self, credential_id: &[u8], sign_count: i32) -> Result<()>;
}

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn create_challenge(&self, challenge: &NewChallenge) -> Result<Challenge>;
    async fn find_challenge(&self, challenge: &str, challenge_type: &str) -> Result<Option<Challenge>>;
    async fn find_and_consume_challenge(&self, challenge: &str, challenge_type: &str) -> Result<Option<Challenge>>;
    async fn cleanup_expired_challenges(&self) -> Result<()>;
}

pub struct PostgresUserRepository {
    pool: Arc<crate::db::Pool>,
}

impl PostgresUserRepository {
    pub fn new(pool: Arc<crate::db::Pool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let username = username.to_string();
        
        let user = tokio::task::spawn_blocking(move || {
            users::table
                .filter(users::username.eq(&username))
                .first::<User>(&mut conn)
                .optional()
        }).await??;
        
        Ok(user)
    }

    async fn create_user(&self, new_user: &NewUser) -> Result<User> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let new_user = new_user.clone();
        
        tokio::task::spawn_blocking(move || {
            diesel::insert_into(users::table)
                .values(&new_user)
                .execute(&mut conn)
        }).await??;
        
        // Find the user we just created
        self.find_by_username(&new_user.username).await?
            .ok_or_else(|| crate::error::AppError::Internal("Failed to retrieve created user".to_string()))
    }

    async fn find_by_id(&self, id: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let id = id.to_string();
        
        let user = tokio::task::spawn_blocking(move || {
            users::table
                .filter(users::id.eq(&id))
                .first::<User>(&mut conn)
                .optional()
        }).await??;
        
        Ok(user)
    }
}

pub struct PostgresCredentialRepository {
    pool: Arc<crate::db::Pool>,
}

impl PostgresCredentialRepository {
    pub fn new(pool: Arc<crate::db::Pool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn find_by_user_id(&self, user_id: &str) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let user_id = user_id.to_string();
        
        let creds = tokio::task::spawn_blocking(move || {
            credentials::table
                .filter(credentials::user_id.eq(&user_id))
                .load::<Credential>(&mut conn)
        }).await??;
        
        Ok(creds)
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let credential_id = credential_id.to_vec();
        
        let cred = tokio::task::spawn_blocking(move || {
            credentials::table
                .filter(credentials::credential_id.eq(&credential_id))
                .first::<Credential>(&mut conn)
                .optional()
        }).await??;
        
        Ok(cred)
    }

    async fn create_credential(&self, new_credential: &NewCredential) -> Result<Credential> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let new_credential = new_credential.clone();
        
        tokio::task::spawn_blocking(move || {
            diesel::insert_into(credentials::table)
                .values(&new_credential)
                .execute(&mut conn)
        }).await??;
        
        // Find the credential we just created
        self.find_by_credential_id(&new_credential.credential_id).await?
            .ok_or_else(|| crate::error::AppError::Internal("Failed to retrieve created credential".to_string()))
    }

    async fn update_sign_count(&self, credential_id: &[u8], sign_count: i32) -> Result<()> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let credential_id = credential_id.to_vec();
        
        tokio::task::spawn_blocking(move || {
            diesel::update(credentials::table.filter(credentials::credential_id.eq(&credential_id)))
                .set((
                    credentials::sign_count.eq(sign_count),
                    credentials::updated_at.eq(Utc::now().to_rfc3339()),
                ))
                .execute(&mut conn)
        }).await??;
        
        Ok(())
    }
}

pub struct PostgresChallengeRepository {
    pool: Arc<crate::db::Pool>,
}

impl PostgresChallengeRepository {
    pub fn new(pool: Arc<crate::db::Pool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeRepository for PostgresChallengeRepository {
    async fn find_challenge(&self, challenge_str: &str, challenge_type: &str) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let challenge_str = challenge_str.to_string();
        let challenge_type = challenge_type.to_string();
        
        let challenge = tokio::task::spawn_blocking(move || {
            challenges::table
                .filter(challenges::challenge.eq(&challenge_str))
                .filter(challenges::challenge_type.eq(&challenge_type))
                .first::<Challenge>(&mut conn)
                .optional()
        }).await??;
        
        Ok(challenge)
    }
    async fn create_challenge(&self, new_challenge: &NewChallenge) -> Result<Challenge> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let new_challenge = new_challenge.clone();
        let challenge_str = new_challenge.challenge.clone();
        
        tokio::task::spawn_blocking(move || {
            diesel::insert_into(challenges::table)
                .values(&new_challenge)
                .execute(&mut conn)
        }).await??;
        
        // Find the challenge we just created
        self.find_and_consume_challenge(&challenge_str, &new_challenge.challenge_type).await?
            .ok_or_else(|| crate::error::AppError::Internal("Failed to retrieve created challenge".to_string()))
    }

    async fn find_and_consume_challenge(&self, challenge_str: &str, challenge_type: &str) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let challenge_str = challenge_str.to_string();
        let challenge_type = challenge_type.to_string();
        let now = Utc::now().to_rfc3339();
        
        let challenge = tokio::task::spawn_blocking(move || {
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                let challenge = challenges::table
                    .filter(challenges::challenge.eq(&challenge_str))
                    .filter(challenges::challenge_type.eq(&challenge_type))
                    .filter(challenges::used.eq(false))
                    .filter(challenges::expires_at.gt(&now))
                    .first::<Challenge>(conn)
                    .optional()?;

                if let Some(ref ch) = challenge {
                    diesel::update(challenges::table.filter(challenges::id.eq(&ch.id)))
                        .set(challenges::used.eq(true))
                        .execute(conn)?;
                }

                Ok(challenge)
            })
        }).await??;
        
        Ok(challenge)
    }

    async fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut conn = self.pool.get()
            .map_err(|e| crate::error::AppError::Internal(format!("Database connection error: {}", e)))?;
        let now = Utc::now().to_rfc3339();
        
        tokio::task::spawn_blocking(move || {
            diesel::delete(
                challenges::table.filter(
                    challenges::expires_at.lt(&now)
                )
            ).execute(&mut conn)
        }).await??;
        
        Ok(())
    }
}