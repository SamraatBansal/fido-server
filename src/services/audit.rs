//! Audit logging service

use uuid::Uuid;
use crate::db::{PooledDb, AuditLogRepository, NewAuditLog, AuditLog};
use crate::error::{AppError, Result};

/// Audit service for logging security events
pub struct AuditService {
    _db: std::marker::PhantomData<()>, // Placeholder for database connection
}

impl AuditService {
    /// Create a new audit service
    pub fn new() -> Self {
        Self {
            _db: std::marker::PhantomData,
        }
    }

    /// Log an audit event
    pub async fn log_event(
        &self,
        conn: &mut PooledDb,
        user_id: Option<Uuid>,
        action: &str,
        success: bool,
        credential_id: Option<&str>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        error_message: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> Result<AuditLog> {
        let new_audit_log = NewAuditLog {
            user_id,
            action: action.to_string(),
            success,
            credential_id: credential_id.map(|s| s.to_string()),
            ip_address: ip_address.map(|s| s.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
            error_message: error_message.map(|s| s.to_string()),
            metadata,
        };

        let audit_log = AuditLogRepository::create(conn, new_audit_log)?;
        
        // Also log to application logs for immediate visibility
        let log_level = if success { log::Level::Info } else { log::Level::Warn };
        log::log!(
            log_level,
            "AUDIT: user_id={:?}, action={}, success={}, credential_id={:?}, ip={:?}, error={:?}",
            user_id, action, success, credential_id, ip_address, error_message
        );

        Ok(audit_log)
    }

    /// Log successful registration
    pub async fn log_registration_success(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        credential_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            Some(user_id),
            "registration",
            true,
            Some(credential_id),
            ip_address,
            user_agent,
            None,
            None,
        ).await
    }

    /// Log failed registration
    pub async fn log_registration_failure(
        &self,
        conn: &mut PooledDb,
        user_id: Option<Uuid>,
        error_message: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            user_id,
            "registration",
            false,
            None,
            ip_address,
            user_agent,
            Some(error_message),
            None,
        ).await
    }

    /// Log successful authentication
    pub async fn log_authentication_success(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        credential_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            Some(user_id),
            "authentication",
            true,
            Some(credential_id),
            ip_address,
            user_agent,
            None,
            None,
        ).await
    }

    /// Log failed authentication
    pub async fn log_authentication_failure(
        &self,
        conn: &mut PooledDb,
        user_id: Option<Uuid>,
        credential_id: Option<&str>,
        error_message: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            user_id,
            "authentication",
            false,
            credential_id,
            ip_address,
            user_agent,
            Some(error_message),
            None,
        ).await
    }

    /// Log credential deletion
    pub async fn log_credential_deletion(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        credential_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            Some(user_id),
            "credential_deletion",
            true,
            Some(credential_id),
            ip_address,
            user_agent,
            None,
            None,
        ).await
    }

    /// Log session creation
    pub async fn log_session_created(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            Some(user_id),
            "session_created",
            true,
            None,
            ip_address,
            user_agent,
            None,
            None,
        ).await
    }

    /// Log session invalidation
    pub async fn log_session_invalidated(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        self.log_event(
            conn,
            Some(user_id),
            "session_invalidated",
            true,
            None,
            ip_address,
            user_agent,
            None,
            None,
        ).await
    }

    /// Get audit logs for a user
    pub async fn get_user_audit_logs(
        &self,
        conn: &mut PooledDb,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLog>> {
        AuditLogRepository::find_by_user_id(conn, user_id, limit, offset)
    }

    /// Log security event
    pub async fn log_security_event(
        &self,
        conn: &mut PooledDb,
        action: &str,
        details: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<AuditLog> {
        let metadata = serde_json::json!({
            "details": details,
            "event_type": "security"
        });

        self.log_event(
            conn,
            None,
            action,
            true,
            None,
            ip_address,
            user_agent,
            None,
            Some(metadata),
        ).await
    }
}

impl Default for AuditService {
    fn default() -> Self {
        Self::new()
    }
}