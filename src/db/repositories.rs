//! Repository pattern implementation

use async_trait::async_trait;
use diesel::prelude::*;
use std::sync::Arc;

use crate::db::models::*;
use crate::error::{AppError, Result};
use crate::schema::{credentials, sessions, users};
use crate::services::session::ChallengeData;
use crate::DbPool;
use chrono::{DateTime, Utc};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &NewUser) -> Result<User>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>>;
    async fn update_user(&self, id: &Uuid, user: &NewUser) -> Result<User>;
    async fn delete_user(&self, id: &Uuid) -> Result<()>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, credential: &NewCredential) -> Result<Credential>;
    async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>>;
    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
    async fn update_sign_count(&self, id: &Uuid, count: i64) -> Result<()>;
    async fn update_last_used(&self, id: &Uuid) -> Result<()>;
    async fn delete_credential(&self, id: &Uuid, user_id: &Uuid) -> Result<()>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create_session(&self, session_id: &str, data: &ChallengeData) -> Result<()>;
    async fn find_by_id(&self, id: &str) -> Result<Option<ChallengeData>>;
    async fn delete_session(&self, id: &str) -> Result<()>;
    async fn count_active_sessions(&self, user_id: &Uuid, now: DateTime<Utc>) -> Result<i64>;
    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<usize>;
}

pub struct DieselUserRepository {
    pool: Arc<DbPool>,
}

impl DieselUserRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for DieselUserRepository {
    async fn create_user(&self, user: &NewUser) -> Result<User> {
        let mut conn = self.pool.get()?;
        let user = diesel::insert_into(users::table)
            .values(user)
            .returning(User::as_returning())
            .get_result(&mut conn)?;
        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .optional()?;
        Ok(user)
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        let user = users::table
            .filter(users::id.eq(id))
            .first::<User>(&mut conn)
            .optional()?;
        Ok(user)
    }

    async fn update_user(&self, id: &Uuid, user: &NewUser) -> Result<User> {
        let mut conn = self.pool.get()?;
        let user = diesel::update(users::table.filter(users::id.eq(id)))
            .set(user)
            .returning(User::as_returning())
            .get_result(&mut conn)?;
        Ok(user)
    }

    async fn delete_user(&self, id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(users::table.filter(users::id.eq(id)))
            .execute(&mut conn)?;
        Ok(())
    }
}

pub struct DieselCredentialRepository {
    pool: Arc<DbPool>,
}

impl DieselCredentialRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for DieselCredentialRepository {
    async fn create_credential(&self, credential: &NewCredential) -> Result<Credential> {
        let mut conn = self.pool.get()?;
        let credential = diesel::insert_into(credentials::table)
            .values(credential)
            .returning(Credential::as_returning())
            .get_result(&mut conn)?;
        Ok(credential)
    }

    async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()?;
        let credential = credentials::table
            .filter(credentials::credential_id.eq(id))
            .first::<Credential>(&mut conn)
            .optional()?;
        Ok(credential)
    }

    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()?;
        let creds = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)?;
        Ok(creds)
    }

    async fn update_sign_count(&self, id: &Uuid, count: i64) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::update(credentials::table.filter(credentials::id.eq(id)))
            .set(credentials::sign_count.eq(count))
            .execute(&mut conn)?;
        Ok(())
    }

    async fn update_last_used(&self, id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::update(credentials::table.filter(credentials::id.eq(id)))
            .set(credentials::last_used_at.eq(chrono::Utc::now()))
            .execute(&mut conn)?;
        Ok(())
    }

    async fn delete_credential(&self, id: &Uuid, user_id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(
            credentials::table
                .filter(credentials::id.eq(id))
                .filter(credentials::user_id.eq(user_id)),
        )
        .execute(&mut conn)?;
        Ok(())
    }
}

pub struct DieselSessionRepository {
    pool: Arc<DbPool>,
}

impl DieselSessionRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for DieselSessionRepository {
    async fn create_session(&self, session: &NewSession) -> Result<Session> {
        let mut conn = self.pool.get()?;
        let session = diesel::insert_into(sessions::table)
            .values(session)
            .returning(Session::as_returning())
            .get_result(&mut conn)?;
        Ok(session)
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<Session>> {
        let mut conn = self.pool.get()?;
        let session = sessions::table
            .filter(sessions::id.eq(id))
            .first::<Session>(&mut conn)
            .optional()?;
        Ok(session)
    }

    async fn find_by_challenge(&self, challenge: &str) -> Result<Option<Session>> {
        let mut conn = self.pool.get()?;
        let session = sessions::table
            .filter(sessions::challenge.eq(challenge))
            .first::<Session>(&mut conn)
            .optional()?;
        Ok(session)
    }

    async fn delete_session(&self, id: &Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(sessions::table.filter(sessions::id.eq(id)))
            .execute(&mut conn)?;
        Ok(())
    }

    async fn cleanup_expired_sessions(&self) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(
            sessions::table.filter(sessions::expires_at.lt(chrono::Utc::now())),
        )
        .execute(&mut conn)?;
        Ok(())
    }
}