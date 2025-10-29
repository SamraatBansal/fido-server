//! Database repository layer

use diesel::prelude::*;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::db::models::*;
use crate::db::PooledPg;
use crate::error::{AppError, Result};
use crate::schema::{challenges, credentials, users};

pub trait UserRepository: Send + Sync {
    fn create_user(&self, new_user: NewUser) -> Result<User>;
    fn find_user_by_username(&self, username: &str) -> Result<Option<User>>;
    fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<User>>;
}

pub trait CredentialRepository: Send + Sync {
    fn create_credential(&self, new_credential: NewCredential) -> Result<Credential>;
    fn find_credentials_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    fn find_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()>;
}

pub trait ChallengeRepository: Send + Sync {
    fn create_challenge(&self, new_challenge: NewChallenge) -> Result<Challenge>;
    fn find_and_consume_challenge(&self, challenge: &str, challenge_type: &str) -> Result<Option<Challenge>>;
    fn cleanup_expired_challenges(&self) -> Result<()>;
}

pub struct PgUserRepository {
    conn: Arc<Mutex<PooledPg>>,
}

impl PgUserRepository {
    pub fn new(conn: PooledPg) -> Self {
        Self { conn: Arc::new(Mutex::new(conn)) }
    }
}

impl UserRepository for PgUserRepository {
    fn create_user(&self, new_user: NewUser) -> Result<User> {
        let mut conn = self.conn.lock().unwrap();
        diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut *conn)
            .map_err(AppError::Database)
    }

    fn find_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.conn.lock().unwrap();
        users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut *conn)
            .optional()
            .map_err(AppError::Database)
    }

    fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        let mut conn = self.conn.lock().unwrap();
        users::table
            .filter(users::id.eq(user_id))
            .first::<User>(&mut *conn)
            .optional()
            .map_err(AppError::Database)
    }
}

pub struct PgCredentialRepository {
    conn: Arc<Mutex<PooledPg>>,
}

impl PgCredentialRepository {
    pub fn new(conn: PooledPg) -> Self {
        Self { conn: Arc::new(Mutex::new(conn)) }
    }
}

impl CredentialRepository for PgCredentialRepository {
    fn create_credential(&self, new_credential: NewCredential) -> Result<Credential> {
        let mut conn = self.conn.lock().unwrap();
        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .returning(Credential::as_returning())
            .get_result(&mut *conn)
            .map_err(AppError::Database)
    }

    fn find_credentials_by_user(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.conn.lock().unwrap();
        credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(&mut *conn)
            .map_err(AppError::Database)
    }

    fn find_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let mut conn = self.conn.lock().unwrap();
        credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut *conn)
            .optional()
            .map_err(AppError::Database)
    }

    fn update_sign_count(&self, credential_id: &[u8], sign_count: i64) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        diesel::update(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .set(credentials::sign_count.eq(sign_count))
            .execute(&mut *conn)
            .map(|_| ())
            .map_err(AppError::Database)
    }
}

pub struct PgChallengeRepository {
    conn: Arc<Mutex<PooledPg>>,
}

impl PgChallengeRepository {
    pub fn new(conn: PooledPg) -> Self {
        Self { conn: Arc::new(Mutex::new(conn)) }
    }
}

impl ChallengeRepository for PgChallengeRepository {
    fn create_challenge(&self, new_challenge: NewChallenge) -> Result<Challenge> {
        let mut conn = self.conn.lock().unwrap();
        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .returning(Challenge::as_returning())
            .get_result(&mut *conn)
            .map_err(AppError::Database)
    }

    fn find_and_consume_challenge(&self, challenge: &str, challenge_type: &str) -> Result<Option<Challenge>> {
        let mut conn = self.conn.lock().unwrap();
        conn.transaction::<Option<Challenge>, _, _>(|conn| {
            let found_challenge = challenges::table
                .filter(challenges::challenge.eq(challenge))
                .filter(challenges::challenge_type.eq(challenge_type))
                .filter(challenges::expires_at.gt(chrono::Utc::now().naive_utc()))
                .first::<Challenge>(conn)
                .optional()
                .map_err(AppError::Database)?;

            if let Some(ref challenge) = found_challenge {
                diesel::delete(challenges::table.filter(challenges::id.eq(challenge.id)))
                    .execute(conn)
                    .map_err(AppError::Database)?;
            }

            Ok(found_challenge)
        })
    }

    fn cleanup_expired_challenges(&self) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(chrono::Utc::now().naive_utc())),
        )
        .execute(&mut *conn)
        .map(|_| ())
        .map_err(AppError::Database)
    }
}