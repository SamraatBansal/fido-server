//! Database repository layer

use diesel::prelude::*;
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use crate::db::models::*;
use crate::db::connection::PooledDb;
use crate::error::{AppError, Result};

/// User repository
pub struct UserRepository;

impl UserRepository {
    /// Create a new user
    pub fn create(conn: &mut PooledDb, new_user: NewUser) -> Result<User> {
        use crate::schema::users;

        diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {}", e)))
    }

    /// Get user by ID
    pub fn find_by_id(conn: &mut PooledDb, user_id: Uuid) -> Result<Option<User>> {
        use crate::schema::users;

        users::table
            .filter(users::id.eq(user_id))
            .first(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user by ID: {}", e)))
    }

    /// Get user by username
    pub fn find_by_username(conn: &mut PooledDb, username: &str) -> Result<Option<User>> {
        use crate::schema::users;

        users::table
            .filter(users::username.eq(username))
            .first(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find user by username: {}", e)))
    }

    /// Get or create user
    pub fn get_or_create(conn: &mut PooledDb, username: &str, display_name: &str) -> Result<User> {
        if let Some(user) = Self::find_by_username(conn, username)? {
            Ok(user)
        } else {
            let new_user = NewUser {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };
            Self::create(conn, new_user)
        }
    }
}

/// Credential repository
pub struct CredentialRepository;

impl CredentialRepository {
    /// Create a new credential
    pub fn create(conn: &mut PooledDb, new_credential: NewCredential) -> Result<Credential> {
        use crate::schema::credentials;

        diesel::insert_into(credentials::table)
            .values(&new_credential)
            .returning(Credential::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create credential: {}", e)))
    }

    /// Get credential by ID
    pub fn find_by_id(conn: &mut PooledDb, credential_id: Uuid) -> Result<Option<Credential>> {
        use crate::schema::credentials;

        credentials::table
            .filter(credentials::id.eq(credential_id))
            .first(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find credential by ID: {}", e)))
    }

    /// Get credential by credential ID string
    pub fn find_by_credential_id(conn: &mut PooledDb, credential_id: &str) -> Result<Option<Credential>> {
        use crate::schema::credentials;

        credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find credential by credential ID: {}", e)))
    }

    /// Get all credentials for a user
    pub fn find_by_user_id(conn: &mut PooledDb, user_id: Uuid) -> Result<Vec<Credential>> {
        use crate::schema::credentials;

        credentials::table
            .filter(credentials::user_id.eq(user_id))
            .order(credentials::created_at.desc())
            .load(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to find credentials for user: {}", e)))
    }

    /// Update credential usage
    pub fn update_usage(conn: &mut PooledDb, credential_id: &str, sign_count: i64) -> Result<()> {
        use crate::schema::credentials;

        diesel::update(credentials::table.filter(credentials::credential_id.eq(credential_id)))
            .set((
                credentials::sign_count.eq(sign_count),
                credentials::last_used_at.eq(Utc::now()),
                credentials::updated_at.eq(Utc::now()),
            ))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to update credential usage: {}", e)))?;

        Ok(())
    }

    /// Delete credential
    pub fn delete(conn: &mut PooledDb, credential_id: Uuid) -> Result<()> {
        use crate::schema::credentials;

        diesel::delete(credentials::table.filter(credentials::id.eq(credential_id)))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete credential: {}", e)))?;

        Ok(())
    }
}

/// Challenge repository
pub struct ChallengeRepository;

impl ChallengeRepository {
    /// Create a new challenge
    pub fn create(conn: &mut PooledDb, new_challenge: NewChallenge) -> Result<Challenge> {
        use crate::schema::challenges;

        diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .returning(Challenge::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create challenge: {}", e)))
    }

    /// Get challenge by challenge ID
    pub fn find_by_challenge_id(conn: &mut PooledDb, challenge_id: Uuid) -> Result<Option<Challenge>> {
        use crate::schema::challenges;

        challenges::table
            .filter(challenges::challenge_id.eq(challenge_id))
            .first(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find challenge: {}", e)))
    }

    /// Mark challenge as used
    pub fn mark_used(conn: &mut PooledDb, challenge_id: Uuid) -> Result<()> {
        use crate::schema::challenges;

        diesel::update(challenges::table.filter(challenges::challenge_id.eq(challenge_id)))
            .set(challenges::used.eq(true))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to mark challenge as used: {}", e)))?;

        Ok(())
    }

    /// Clean up expired challenges
    pub fn cleanup_expired(conn: &mut PooledDb) -> Result<usize> {
        use crate::schema::challenges;

        let deleted_count = diesel::delete(
            challenges::table.filter(
                challenges::expires_at.lt(Utc::now())
            )
        )
        .execute(conn)
        .map_err(|e| AppError::DatabaseError(format!("Failed to cleanup expired challenges: {}", e)))?;

        Ok(deleted_count)
    }
}

/// Session repository
pub struct SessionRepository;

impl SessionRepository {
    /// Create a new session
    pub fn create(conn: &mut PooledDb, new_session: NewSession) -> Result<Session> {
        use crate::schema::sessions;

        diesel::insert_into(sessions::table)
            .values(&new_session)
            .returning(Session::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create session: {}", e)))
    }

    /// Get session by token
    pub fn find_by_token(conn: &mut PooledDb, session_token: &str) -> Result<Option<Session>> {
        use crate::schema::sessions;

        sessions::table
            .filter(sessions::session_token.eq(session_token))
            .filter(sessions::expires_at.gt(Utc::now()))
            .first(conn)
            .optional()
            .map_err(|e| AppError::DatabaseError(format!("Failed to find session: {}", e)))
    }

    /// Update session last accessed
    pub fn update_accessed(conn: &mut PooledDb, session_id: Uuid) -> Result<()> {
        use crate::schema::sessions;

        diesel::update(sessions::table.filter(sessions::id.eq(session_id)))
            .set(sessions::last_accessed_at.eq(Utc::now()))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to update session access: {}", e)))?;

        Ok(())
    }

    /// Delete session
    pub fn delete(conn: &mut PooledDb, session_id: Uuid) -> Result<()> {
        use crate::schema::sessions;

        diesel::delete(sessions::table.filter(sessions::id.eq(session_id)))
            .execute(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete session: {}", e)))?;

        Ok(())
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(conn: &mut PooledDb) -> Result<usize> {
        use crate::schema::sessions;

        let deleted_count = diesel::delete(
            sessions::table.filter(
                sessions::expires_at.lt(Utc::now())
            )
        )
        .execute(conn)
        .map_err(|e| AppError::DatabaseError(format!("Failed to cleanup expired sessions: {}", e)))?;

        Ok(deleted_count)
    }
}

/// Audit log repository
pub struct AuditLogRepository;

impl AuditLogRepository {
    /// Create a new audit log entry
    pub fn create(conn: &mut PooledDb, new_audit_log: NewAuditLog) -> Result<AuditLog> {
        use crate::schema::audit_logs;

        diesel::insert_into(audit_logs::table)
            .values(&new_audit_log)
            .returning(AuditLog::as_returning())
            .get_result(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to create audit log: {}", e)))
    }

    /// Get audit logs for a user
    pub fn find_by_user_id(
        conn: &mut PooledDb,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLog>> {
        use crate::schema::audit_logs;

        audit_logs::table
            .filter(audit_logs::user_id.eq(user_id))
            .order(audit_logs::created_at.desc())
            .limit(limit)
            .offset(offset)
            .load(conn)
            .map_err(|e| AppError::DatabaseError(format!("Failed to find audit logs: {}", e)))
    }
}