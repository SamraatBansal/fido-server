//! Database repositories

use async_trait::async_trait;
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::webauthn::service::{ChallengeStore, UserRepository, CredentialRepository};
use super::models::*;

/// Type alias for database connection pool
pub type DbPool = r2d2::Pool<ConnectionManager<diesel::PgConnection>>;

/// PostgreSQL challenge store
#[derive(Debug, Clone)]
pub struct PostgresChallengeStore {
    pool: Arc<DbPool>,
}

impl PostgresChallengeStore {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeStore for PostgresChallengeStore {
    async fn store_challenge(&self, challenge: &str, username: &str, expires_at: chrono::DateTime<Utc>) -> Result<()> {
        let pool = self.pool.clone();
        let challenge = challenge.to_string();
        let username = username.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let new_challenge = NewChallenge {
                id: uuid::Uuid::new_v4().to_string(),
                challenge,
                username,
                expires_at,
                created_at: Utc::now(),
            };
            
            diesel::insert_into(crate::db::schema::challenges::table)
                .values(&new_challenge)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to store challenge: {}", e)))?;
            
            Ok::<(), AppError>(())
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn validate_and_consume_challenge(&self, challenge: &str, username: &str) -> Result<bool> {
        let pool = self.pool.clone();
        let challenge = challenge.to_string();
        let username = username.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let now = Utc::now();
            
            // Find and delete the challenge
            let deleted_count = diesel::delete(
                crate::db::schema::challenges::table.filter(
                    crate::db::schema::challenges::challenge.eq(&challenge)
                        .and(crate::db::schema::challenges::username.eq(&username))
                        .and(crate::db::schema::challenges::expires_at.gt(now))
                )
            ).execute(&mut conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to validate challenge: {}", e)))?;
            
            Ok(deleted_count > 0)
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn cleanup_expired_challenges(&self) -> Result<()> {
        let pool = self.pool.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let now = Utc::now();
            
            diesel::delete(crate::db::schema::challenges::table.filter(crate::db::schema::challenges::expires_at.lt(now)))
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to cleanup challenges: {}", e)))?;
            
            Ok::<(), AppError>(())
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }
}

/// PostgreSQL user repository
#[derive(Debug, Clone)]
pub struct PostgresUserRepository {
    pool: Arc<DbPool>,
}

impl PostgresUserRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(&self, new_user: WebAuthnNewUser) -> Result<WebAuthnUser> {
        let pool = self.pool.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let db_new_user = NewUser {
                id: new_user.id,
                username: new_user.username,
                display_name: new_user.display_name,
                created_at: new_user.created_at,
                updated_at: Utc::now(),
            };
            
            diesel::insert_into(users::table)
                .values(&db_new_user)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))?;
            
            let user: User = users::table
                .filter(users::id.eq(&db_new_user.id))
                .first(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to retrieve created user: {}", e)))?;
            
            Ok(WebAuthnUser {
                id: user.id,
                username: user.username,
                display_name: user.display_name,
                created_at: user.created_at,
                updated_at: user.updated_at,
            })
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<WebAuthnUser>> {
        let pool = self.pool.clone();
        let username = username.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let user: Option<User> = users::table
                .filter(users::username.eq(&username))
                .first(&mut conn)
                .optional()
                .map_err(|e| AppError::DatabaseError(format!("Failed to get user: {}", e)))?;
            
            Ok(user.map(|u| WebAuthnUser {
                id: u.id,
                username: u.username,
                display_name: u.display_name,
                created_at: u.created_at,
                updated_at: u.updated_at,
            }))
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn update_user(&self, user: WebAuthnUser) -> Result<WebAuthnUser> {
        let pool = self.pool.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            diesel::update(users::table.filter(users::id.eq(&user.id)))
                .((
                    users::username.eq(&user.username),
                    users::display_name.eq(&user.display_name),
                    users::updated_at.eq(Utc::now()),
                ))
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to update user: {}", e)))?;
            
            let updated_user: User = users::table
                .filter(users::id.eq(&user.id))
                .first(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to retrieve updated user: {}", e)))?;
            
            Ok(WebAuthnUser {
                id: updated_user.id,
                username: updated_user.username,
                display_name: updated_user.display_name,
                created_at: updated_user.created_at,
                updated_at: updated_user.updated_at,
            })
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn delete_user(&self, user_id: &str) -> Result<()> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            diesel::delete(users::table.filter(users::id.eq(&user_id)))
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to delete user: {}", e)))?;
            
            Ok::<(), AppError>(())
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }
}

/// PostgreSQL credential repository
#[derive(Debug, Clone)]
pub struct PostgresCredentialRepository {
    pool: Arc<DbPool>,
}

impl PostgresCredentialRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn store_credential(&self, new_credential: WebAuthnNewCredential) -> Result<WebAuthnCredential> {
        let pool = self.pool.clone();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let db_new_credential = NewCredential {
                id: new_credential.id,
                user_id: new_credential.user_id,
                public_key: new_credential.public_key,
                sign_count: new_credential.sign_count as i32,
                created_at: new_credential.created_at,
                attestation_format: new_credential.attestation_format,
                aaguid: new_credential.aaguid,
            };
            
            diesel::insert_into(credentials::table)
                .values(&db_new_credential)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to store credential: {}", e)))?;
            
            let credential: Credential = credentials::table
                .filter(credentials::id.eq(&db_new_credential.id))
                .first(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to retrieve stored credential: {}", e)))?;
            
            Ok(WebAuthnCredential {
                id: credential.id,
                user_id: credential.user_id,
                public_key: credential.public_key,
                sign_count: credential.sign_count as u32,
                created_at: credential.created_at,
                attestation_format: credential.attestation_format,
                aaguid: credential.aaguid,
            })
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn get_credential_by_id(&self, id: &str) -> Result<Option<WebAuthnCredential>> {
        let pool = self.pool.clone();
        let id = id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let credential: Option<Credential> = credentials::table
                .filter(credentials::id.eq(&id))
                .first(&mut conn)
                .optional()
                .map_err(|e| AppError::DatabaseError(format!("Failed to get credential: {}", e)))?;
            
            Ok(credential.map(|c| WebAuthnCredential {
                id: c.id,
                user_id: c.user_id,
                public_key: c.public_key,
                sign_count: c.sign_count as u32,
                created_at: c.created_at,
                attestation_format: c.attestation_format,
                aaguid: c.aaguid,
            }))
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn get_credentials_by_user(&self, user_id: &str) -> Result<Vec<WebAuthnCredential>> {
        let pool = self.pool.clone();
        let user_id = user_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            let credentials: Vec<Credential> = credentials::table
                .filter(credentials::user_id.eq(&user_id))
                .load(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to get credentials: {}", e)))?;
            
            Ok(credentials.into_iter().map(|c| WebAuthnCredential {
                id: c.id,
                user_id: c.user_id,
                public_key: c.public_key,
                sign_count: c.sign_count as u32,
                created_at: c.created_at,
                attestation_format: c.attestation_format,
                aaguid: c.aaguid,
            }).collect())
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn update_sign_count(&self, credential_id: &str, count: u32) -> Result<()> {
        let pool = self.pool.clone();
        let credential_id = credential_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            diesel::update(credentials::table.filter(credentials::id.eq(&credential_id)))
                .credentials::sign_count.eq(count as i32)
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to update sign count: {}", e)))?;
            
            Ok::<(), AppError>(())
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }

    async fn delete_credential(&self, credential_id: &str) -> Result<()> {
        let pool = self.pool.clone();
        let credential_id = credential_id.to_string();
        
        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()
                .map_err(|e| AppError::DatabaseError(format!("Connection error: {}", e)))?;
            
            diesel::delete(credentials::table.filter(credentials::id.eq(&credential_id)))
                .execute(&mut conn)
                .map_err(|e| AppError::DatabaseError(format!("Failed to delete credential: {}", e)))?;
            
            Ok::<(), AppError>(())
        }).await.map_err(|e| AppError::InternalError(format!("Task join error: {}", e)))?
    }
}