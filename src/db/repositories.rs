use crate::db::{models::*, PgPooledConn};
use crate::error::{AppError, Result};
use async_trait::async_trait;
use diesel::prelude::*;
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &NewUser) -> Result<User>;
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn update_last_login(&self, id: &Uuid) -> Result<()>;
    async fn delete_user(&self, id: &Uuid) -> Result<()>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn create_credential(&self, credential: &NewCredential) -> Result<Credential>;
    async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>>;
    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>>;
    async fn update_sign_count(&self, id: &[u8], count: i64) -> Result<()>;
    async fn update_last_used(&self, id: &[u8]) -> Result<()>;
    async fn delete_credential(&self, id: &[u8]) -> Result<()>;
    async fn delete_by_user_id(&self, user_id: &Uuid) -> Result<()>;
}

#[async_trait]
pub trait AuthSessionRepository: Send + Sync {
    async fn create_session(&self, session: &NewAuthSession) -> Result<AuthSession>;
    async fn find_by_session_id(&self, session_id: &str) -> Result<Option<AuthSession>>;
    async fn delete_session(&self, session_id: &str) -> Result<()>;
    async fn delete_expired_sessions(&self) -> Result<()>;
}

#[async_trait]
pub trait AuditLogRepository: Send + Sync {
    async fn create_log(&self, log: &NewAuditLog) -> Result<AuditLog>;
    async fn find_by_user_id(&self, user_id: &Uuid, limit: i64) -> Result<Vec<AuditLog>>;
}

pub struct PgUserRepository {
    pool: crate::db::PgPool,
}

impl PgUserRepository {
    pub fn new(pool: crate::db::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create_user(&self, user: &NewUser) -> Result<User> {
        use crate::db::schema::users;

        let mut conn = self.pool.get()?;
        let user: User = diesel::insert_into(users::table)
            .values(user)
            .returning(User::as_returning())
            .get_result(&mut conn)?;

        Ok(user)
    }

    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>> {
        use crate::db::schema::users;

        let mut conn = self.pool.get()?;
        let user = users::table
            .filter(users::id.eq(id))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        use crate::db::schema::users;

        let mut conn = self.pool.get()?;
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user)
    }

    async fn update_last_login(&self, id: &Uuid) -> Result<()> {
        use crate::db::schema::users;
        use diesel::dsl::now;

        let mut conn = self.pool.get()?;
        diesel::update(users::table.filter(users::id.eq(id)))
            .set(users::last_login_at.eq(now))
            .execute(&mut conn)?;

        Ok(())
    }

    async fn delete_user(&self, id: &Uuid) -> Result<()> {
        use crate::db::schema::users;

        let mut conn = self.pool.get()?;
        diesel::delete(users::table.filter(users::id.eq(id))).execute(&mut conn)?;

        Ok(())
    }
}

pub struct PgCredentialRepository {
    pool: crate::db::PgPool,
}

impl PgCredentialRepository {
    pub fn new(pool: crate::db::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CredentialRepository for PgCredentialRepository {
    async fn create_credential(&self, credential: &NewCredential) -> Result<Credential> {
        use crate::db::schema::credentials;

        let mut conn = self.pool.get()?;
        let credential: Credential = diesel::insert_into(credentials::table)
            .values(credential)
            .returning(Credential::as_returning())
            .get_result(&mut conn)?;

        Ok(credential)
    }

    async fn find_by_credential_id(&self, id: &[u8]) -> Result<Option<Credential>> {
        use crate::db::schema::credentials;

        let mut conn = self.pool.get()?;
        let credential = credentials::table
            .filter(credentials::credential_id.eq(id))
            .first::<Credential>(&mut conn)
            .optional()?;

        Ok(credential)
    }

    async fn find_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Credential>> {
        use crate::db::schema::credentials;

        let mut conn = self.pool.get()?;
        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)?;

        Ok(credentials)
    }

    async fn update_sign_count(&self, id: &[u8], count: i64) -> Result<()> {
        use crate::db::schema::credentials;

        let mut conn = self.pool.get()?;
        diesel::update(credentials::table.filter(credentials::credential_id.eq(id)))
            .set(credentials::sign_count.eq(count))
            .execute(&mut conn)?;

        Ok(())
    }

    async fn update_last_used(&self, id: &[u8]) -> Result<()> {
        use crate::db::schema::credentials;
        use diesel::dsl::now;

        let mut conn = self.pool.get()?;
        diesel::update(credentials::table.filter(credentials::credential_id.eq(id)))
            .set(credentials::last_used_at.eq(now))
            .execute(&mut conn)?;

        Ok(())
    }

    async fn delete_credential(&self, id: &[u8]) -> Result<()> {
        use crate::db::schema::credentials;

        let mut conn = self.pool.get()?;
        diesel::delete(credentials::table.filter(credentials::credential_id.eq(id)))
            .execute(&mut conn)?;

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: &Uuid) -> Result<()> {
        use crate::db::schema::credentials;

        let mut conn = self.pool.get()?;
        diesel::delete(credentials::table.filter(credentials::user_id.eq(user_id)))
            .execute(&mut conn)?;

        Ok(())
    }
}

pub struct PgAuthSessionRepository {
    pool: crate::db::PgPool,
}

impl PgAuthSessionRepository {
    pub fn new(pool: crate::db::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthSessionRepository for PgAuthSessionRepository {
    async fn create_session(&self, session: &NewAuthSession) -> Result<AuthSession> {
        use crate::db::schema::auth_sessions;

        let mut conn = self.pool.get()?;
        let session: AuthSession = diesel::insert_into(auth_sessions::table)
            .values(session)
            .returning(AuthSession::as_returning())
            .get_result(&mut conn)?;

        Ok(session)
    }

    async fn find_by_session_id(&self, session_id: &str) -> Result<Option<AuthSession>> {
        use crate::db::schema::auth_sessions;

        let mut conn = self.pool.get()?;
        let session = auth_sessions::table
            .filter(auth_sessions::session_id.eq(session_id))
            .first::<AuthSession>(&mut conn)
            .optional()?;

        Ok(session)
    }

    async fn delete_session(&self, session_id: &str) -> Result<()> {
        use crate::db::schema::auth_sessions;

        let mut conn = self.pool.get()?;
        diesel::delete(auth_sessions::table.filter(auth_sessions::session_id.eq(session_id)))
            .execute(&mut conn)?;

        Ok(())
    }

    async fn delete_expired_sessions(&self) -> Result<()> {
        use crate::db::schema::auth_sessions;
        use diesel::dsl::now;

        let mut conn = self.pool.get()?;
        diesel::delete(auth_sessions::table.filter(auth_sessions::expires_at.lt(now)))
            .execute(&mut conn)?;

        Ok(())
    }
}

pub struct PgAuditLogRepository {
    pool: crate::db::PgPool,
}

impl PgAuditLogRepository {
    pub fn new(pool: crate::db::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditLogRepository for PgAuditLogRepository {
    async fn create_log(&self, log: &NewAuditLog) -> Result<AuditLog> {
        use crate::db::schema::audit_logs;

        let mut conn = self.pool.get()?;
        let log: AuditLog = diesel::insert_into(audit_logs::table)
            .values(log)
            .returning(AuditLog::as_returning())
            .get_result(&mut conn)?;

        Ok(log)
    }

    async fn find_by_user_id(&self, user_id: &Uuid, limit: i64) -> Result<Vec<AuditLog>> {
        use crate::db::schema::audit_logs;

        let mut conn = self.pool.get()?;
        let logs = audit_logs::table
            .filter(audit_logs::user_id.eq(user_id))
            .order(audit_logs::created_at.desc())
            .limit(limit)
            .load::<AuditLog>(&mut conn)?;

        Ok(logs)
    }
}
