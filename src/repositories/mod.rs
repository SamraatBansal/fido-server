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
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    async fn create_credential(&self, credential: &NewCredential) -> Result<Credential>;
    async fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()>;
}

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn create_challenge(&self, challenge: &NewChallenge) -> Result<Challenge>;
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

impl UserRepository for PostgresUserRepository {
    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
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
        let mut conn = self.pool.get()?;
        let new_user = new_user.clone();
        
        let user = tokio::task::spawn_blocking(move || {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(User::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(user)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        
        let user = tokio::task::spawn_blocking(move || {
            users::table
                .filter(users::id.eq(id))
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

impl CredentialRepository for PostgresCredentialRepository {
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()?;
        
        let creds = tokio::task::spawn_blocking(move || {
            credentials::table
                .filter(credentials::user_id.eq(user_id))
                .load::<Credential>(&mut conn)
        }).await??;
        
        Ok(creds)
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()?;
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
        let mut conn = self.pool.get()?;
        let new_credential = new_credential.clone();
        
        let cred = tokio::task::spawn_blocking(move || {
            diesel::insert_into(credentials::table)
                .values(&new_credential)
                .returning(Credential::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(cred)
    }

    async fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()> {
        let mut conn = self.pool.get()?;
        let credential_id = credential_id.to_vec();
        
        tokio::task::spawn_blocking(move || {
            diesel::update(credentials::table.filter(credentials::credential_id.eq(&credential_id)))
                .set((
                    credentials::sign_count.eq(sign_count),
                    credentials::updated_at.eq(Utc::now()),
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

impl ChallengeRepository for PostgresChallengeRepository {
    async fn create_challenge(&self, new_challenge: &NewChallenge) -> Result<Challenge> {
        let mut conn = self.pool.get()?;
        let new_challenge = new_challenge.clone();
        
        let challenge = tokio::task::spawn_blocking(move || {
            diesel::insert_into(challenges::table)
                .values(&new_challenge)
                .returning(Challenge::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(challenge)
    }

    async fn find_and_consume_challenge(&self, challenge_str: &str, challenge_type: &str) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()?;
        let challenge_str = challenge_str.to_string();
        let challenge_type = challenge_type.to_string();
        
        let challenge = tokio::task::spawn_blocking(move || {
            conn.transaction::<_, diesel::result::Error, _>(|conn| {
                let challenge = challenges::table
                    .filter(challenges::challenge.eq(&challenge_str))
                    .filter(challenges::challenge_type.eq(&challenge_type))
                    .filter(challenges::used.eq(false))
                    .filter(challenges::expires_at.gt(Utc::now()))
                    .first::<Challenge>(conn)
                    .optional()?;

                if let Some(ref ch) = challenge {
                    diesel::update(challenges::table.filter(challenges::id.eq(ch.id)))
                        .set(challenges::used.eq(true))
                        .execute(conn)?;
                }

                Ok(challenge)
            })
        }).await??;
        
        Ok(challenge)
    }

    async fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut conn = self.pool.get()?;
        
        tokio::task::spawn_blocking(move || {
            diesel::delete(
                challenges::table.filter(
                    challenges::expires_at.lt(Utc::now())
                )
            ).execute(&mut conn)
        }).await??;
        
        Ok(())
    }
}