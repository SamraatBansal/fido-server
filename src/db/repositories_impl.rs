//! Database repository implementations

use std::sync::Arc;
use diesel::prelude::*;
use async_trait::async_trait;
use uuid::Uuid;
use chrono::Utc;

use crate::db::connection::PgPool;
use crate::db::models::{User, NewUser, UpdateUser, Credential, NewCredential, UpdateCredential, Challenge, NewChallenge};
use crate::db::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use crate::models::{ChallengeType, StoredChallenge};
use crate::error::{AppError, Result};

/// PostgreSQL user repository
pub struct PgUserRepository {
    pool: Arc<PgPool>,
}

impl PgUserRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create_user(&self, username: &str, display_name: &str) -> Result<crate::models::User> {
        use crate::schema::users;
        
        let new_user = NewUser {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
        };

        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let user: User = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(user.into())
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<crate::models::User>> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let user: Option<User> = users::table
            .filter(users::username.eq(username))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(e))?;

        Ok(user.map(|u| u.into()))
    }

    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<crate::models::User>> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let user: Option<User> = users::table
            .filter(users::id.eq(user_id))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(e))?;

        Ok(user.map(|u| u.into()))
    }

    async fn update_user(&self, user: &crate::models::User) -> Result<()> {
        use crate::schema::users;
        
        let update_user = UpdateUser {
            username: Some(user.username.clone()),
            display_name: Some(user.display_name.clone()),
            updated_at: Utc::now(),
        };

        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        diesel::update(users::table.filter(users::id.eq(user.id)))
            .set(&update_user)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<()> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        diesel::delete(users::table.filter(users::id.eq(user_id)))
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }
}

/// PostgreSQL credential repository
pub struct PgCredentialRepository {
    pool: Arc<PgPool>,
}

impl PgCredentialRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for PgCredentialRepository {
    async fn create_credential(&self, credential: &crate::models::Credential) -> Result<()> {
        use crate::schema::credentials;
        
        let new_credential = NewCredential::try_from(credential.clone())
            .map_err(|e| AppError::Serialization(e))?;

        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<crate::models::Credential>> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let credential: Option<Credential> = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(e))?;

        match credential {
            Some(cred) => {
                let model_credential = crate::models::Credential::try_from(cred)
                    .map_err(|e| AppError::Serialization(e))?;
                Ok(Some(model_credential))
            }
            None => Ok(None),
        }
    }

    async fn get_credentials_for_user(&self, user_id: Uuid) -> Result<Vec<crate::models::Credential>> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let credentials: Vec<Credential> = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        let mut result = Vec::new();
        for cred in credentials {
            result.push(crate::models::Credential::try_from(cred)
                .map_err(|e| AppError::Serialization(e))?);
        }

        Ok(result)
    }

    async fn update_credential(&self, credential: &crate::models::Credential) -> Result<()> {
        use crate::schema::credentials;
        
        let update_credential = UpdateCredential {
            sign_count: Some(credential.sign_count as i32),
            updated_at: Utc::now(),
        };

        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        diesel::update(credentials::table.filter(credentials::id.eq(credential.id)))
            .set(&update_credential)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    async fn delete_credential(&self, credential_id: &[u8]) -> Result<()> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        diesel::delete(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }
}

/// PostgreSQL challenge repository
pub struct PgChallengeRepository {
    pool: Arc<PgPool>,
}

impl PgChallengeRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeRepository for PgChallengeRepository {
    async fn store_challenge(&self, challenge: &StoredChallenge) -> Result<()> {
        use crate::schema::challenges;
        
        let new_challenge = NewChallenge::from(challenge.clone());

        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(())
    }

    async fn get_challenge(&self, challenge: &str, _challenge_type: ChallengeType) -> Result<Option<StoredChallenge>> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let challenge_record: Option<Challenge> = challenges::table
            .filter(challenges::challenge.eq(challenge))
            .first(&mut conn)
            .optional()
            .map_err(|e| AppError::Database(e))?;

        match challenge_record {
            Some(ch) => {
                let stored_challenge = StoredChallenge::try_from(ch)?;
                Ok(Some(stored_challenge))
            }
            None => Ok(None),
        }
    }

    async fn consume_challenge(&self, challenge: &str, _challenge_type: ChallengeType) -> Result<Option<StoredChallenge>> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let challenge_record: Option<Challenge> = conn.transaction(|conn| {
            let ch: Option<Challenge> = challenges::table
                .filter(challenges::challenge.eq(challenge))
                .first(conn)
                .optional()?;

            if ch.is_some() {
                diesel::delete(challenges::table.filter(challenges::challenge.eq(challenge)))
                    .execute(conn)?;
            }

            Ok(ch)
        }).map_err(|e| AppError::Database(e))?;

        match challenge_record {
            Some(ch) => {
                let stored_challenge = StoredChallenge::try_from(ch)?;
                Ok(Some(stored_challenge))
            }
            None => Ok(None),
        }
    }

    async fn cleanup_expired_challenges(&self) -> Result<u64> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()
            .map_err(|e| AppError::DatabaseConnection(e))?;

        let count = diesel::delete(challenges::table.filter(challenges::expires_at.lt(Utc::now())))
            .execute(&mut conn)
            .map_err(|e| AppError::Database(e))?;

        Ok(count as u64)
    }
}