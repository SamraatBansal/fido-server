//! Database repository implementations

use async_trait::async_trait;
use diesel::prelude::*;
use uuid::Uuid;
use std::sync::Arc;
use tokio::task;

use crate::db::connection::DbPool;
use crate::db::models::{User, Credential, Challenge, NewUser, NewCredential, NewChallenge};
use crate::schema::{users, credentials, challenges};
use crate::services::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use crate::error::Result;

/// PostgreSQL user repository
pub struct PgUserRepository {
    pool: Arc<DbPool>,
}

impl PgUserRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let pool = Arc::clone(&self.pool);
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            users::table
                .filter(users::id.eq(id))
                .first::<User>(&mut conn)
                .optional()
        }).await??;
        
        Ok(result)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let pool = Arc::clone(&self.pool);
        let username = username.to_string();
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            users::table
                .filter(users::username.eq(username))
                .first::<User>(&mut conn)
                .optional()
        }).await??;
        
        Ok(result)
    }

    async fn create(&self, user: &NewUser) -> Result<User> {
        let pool = Arc::clone(&self.pool);
        let user = user.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(users::table)
                .values(&user)
                .returning(User::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(result)
    }

    async fn update(&self, user: &User) -> Result<User> {
        let pool = Arc::clone(&self.pool);
        let user_id = user.id;
        let display_name = user.display_name.clone();
        let email = user.email.clone();
        
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(users::table.filter(users::id.eq(user_id)))
                .values((
                    users::display_name.eq(display_name),
                    users::email.eq(email),
                    users::updated_at.eq(diesel::dsl::now),
                ))
                .returning(User::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(result)
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let pool = Arc::clone(&self.pool);
        task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(users::table.filter(users::id.eq(id)))
                .execute(&mut conn)?;
            Ok::<(), diesel::result::Error>(())
        }).await??;
        
        Ok(())
    }
}

/// PostgreSQL credential repository
pub struct PgCredentialRepository {
    pool: Arc<DbPool>,
}

impl PgCredentialRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for PgCredentialRepository {
    async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>> {
        let pool = Arc::clone(&self.pool);
        let id = id.to_vec();
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            credentials::table
                .filter(credentials::credential_id.eq(id))
                .first::<Credential>(&mut conn)
                .optional()
        }).await??;
        
        Ok(result)
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let pool = Arc::clone(&self.pool);
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            credentials::table
                .filter(credentials::user_id.eq(user_id))
                .load::<Credential>(&mut conn)
        }).await??;
        
        Ok(result)
    }

    async fn create(&self, credential: &NewCredential) -> Result<Credential> {
        let pool = Arc::clone(&self.pool);
        let credential = credential.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(credentials::table)
                .values(&credential)
                .returning(Credential::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(result)
    }

    async fn update_sign_count(&self, id: Uuid, count: i64) -> Result<()> {
        let pool = Arc::clone(&self.pool);
        task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(credentials::table.filter(credentials::id.eq(id)))
                .values((
                    credentials::sign_count.eq(count),
                    credentials::updated_at.eq(diesel::dsl::now),
                ))
                .execute(&mut conn)?;
            Ok::<(), diesel::result::Error>(())
        }).await??;
        
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let pool = Arc::clone(&self.pool);
        task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(credentials::table.filter(credentials::id.eq(id)))
                .execute(&mut conn)?;
            Ok::<(), diesel::result::Error>(())
        }).await??;
        
        Ok(())
    }
}

/// PostgreSQL challenge repository
pub struct PgChallengeRepository {
    pool: Arc<DbPool>,
}

impl PgChallengeRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ChallengeRepository for PgChallengeRepository {
    async fn find_by_challenge(&self, challenge: &str) -> Result<Option<Challenge>> {
        let pool = Arc::clone(&self.pool);
        let challenge = challenge.to_string();
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            challenges::table
                .filter(challenges::challenge.eq(challenge))
                .first::<Challenge>(&mut conn)
                .optional()
        }).await??;
        
        Ok(result)
    }

    async fn create(&self, challenge: &NewChallenge) -> Result<Challenge> {
        let pool = Arc::clone(&self.pool);
        let challenge = challenge.clone();
        let result = task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::insert_into(challenges::table)
                .values(&challenge)
                .returning(Challenge::as_returning())
                .get_result(&mut conn)
        }).await??;
        
        Ok(result)
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let pool = Arc::clone(&self.pool);
        task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(challenges::table.filter(challenges::id.eq(id)))
                .execute(&mut conn)?;
            Ok::<(), diesel::result::Error>(())
        }).await??;
        
        Ok(())
    }

    async fn delete_expired(&self) -> Result<()> {
        let pool = Arc::clone(&self.pool);
        task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(challenges::table.filter(challenges::expires_at.lt(diesel::dsl::now)))
                .execute(&mut conn)?;
            Ok::<(), diesel::result::Error>(())
        }).await??;
        
        Ok(())
    }
}