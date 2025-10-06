//! Audit logging utilities for security events
//! 
//! This module provides comprehensive audit logging for all security-relevant
//! events in the FIDO2/WebAuthn server.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Audit event severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecurityEventType {
    // Registration events
    RegistrationStartAttempt,
    RegistrationChallengeCreated,
    RegistrationFinishAttempt,
    RegistrationCompleted,
    RegistrationFailed,
    
    // Authentication events
    AuthenticationStartAttempt,
    AuthenticationChallengeCreated,
    AuthenticationFinishAttempt,
    AuthenticationCompleted,
    AuthenticationFailed,
    
    // Security events
    ReplayAttackDetected,
    AuthenticationCredentialMismatch,
    InvalidSessionState,
    RateLimitExceeded,
    SuspiciousActivity,
    
    // System events
    SessionCreated,
    SessionExpired,
    SessionDeleted,
    CredentialCreated,
    CredentialUpdated,
    CredentialDeleted,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: SecurityEventType,
    pub severity: AuditSeverity,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub credential_id: Option<String>,
    pub details: Option<Value>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Audit logger trait for different backends
#[async_trait::async_trait]
pub trait AuditLogger: Send + Sync {
    async fn log_security_event(
        &self,
        event_type: &str,
        username: Option<&str>,
        client_ip: Option<&str>,
        details: Option<Value>,
    ) -> Result<()>;

    async fn log_audit_entry(&self, entry: AuditLogEntry) -> Result<()>;

    async fn search_audit_logs(
        &self,
        filters: AuditLogFilters,
    ) -> Result<Vec<AuditLogEntry>>;
}

/// Filters for audit log searches
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogFilters {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub event_types: Option<Vec<SecurityEventType>>,
    pub user_id: Option<String>,
    pub username: Option<String>,
    pub client_ip: Option<String>,
    pub severity: Option<AuditSeverity>,
    pub success: Option<bool>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Default audit logger implementation
pub struct DefaultAuditLogger {
    // In production, this would connect to a proper audit log storage
    // For now, we'll implement a basic in-memory logger for demonstration
}

impl DefaultAuditLogger {
    pub fn new() -> Self {
        Self {}
    }

    /// Create an audit log entry
    fn create_audit_entry(
        &self,
        event_type: &str,
        username: Option<&str>,
        client_ip: Option<&str>,
        details: Option<Value>,
        success: bool,
        error_message: Option<String>,
    ) -> Result<AuditLogEntry> {
        let security_event_type = self.parse_event_type(event_type)?;
        let severity = self.determine_severity(&security_event_type, success);

        Ok(AuditLogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: security_event_type,
            severity,
            user_id: None, // Would be populated from user lookup
            username: username.map(|s| s.to_string()),
            client_ip: client_ip.map(|s| s.to_string()),
            user_agent: None, // Would be extracted from request headers
            session_id: details.as_ref()
                .and_then(|d| d.get("session_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            credential_id: details.as_ref()
                .and_then(|d| d.get("credential_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            details,
            success,
            error_message,
        })
    }

    /// Parse event type string to enum
    fn parse_event_type(&self, event_type: &str) -> Result<SecurityEventType> {
        match event_type {
            "registration_start_attempt" => Ok(SecurityEventType::RegistrationStartAttempt),
            "registration_challenge_created" => Ok(SecurityEventType::RegistrationChallengeCreated),
            "registration_finish_attempt" => Ok(SecurityEventType::RegistrationFinishAttempt),
            "registration_completed" => Ok(SecurityEventType::RegistrationCompleted),
            "registration_failed" => Ok(SecurityEventType::RegistrationFailed),
            
            "authentication_start_attempt" => Ok(SecurityEventType::AuthenticationStartAttempt),
            "authentication_challenge_created" => Ok(SecurityEventType::AuthenticationChallengeCreated),
            "authentication_finish_attempt" => Ok(SecurityEventType::AuthenticationFinishAttempt),
            "authentication_completed" => Ok(SecurityEventType::AuthenticationCompleted),
            "authentication_failed" => Ok(SecurityEventType::AuthenticationFailed),
            
            "replay_attack_detected" => Ok(SecurityEventType::ReplayAttackDetected),
            "authentication_credential_mismatch" => Ok(SecurityEventType::AuthenticationCredentialMismatch),
            "invalid_session_state" => Ok(SecurityEventType::InvalidSessionState),
            "rate_limit_exceeded" => Ok(SecurityEventType::RateLimitExceeded),
            "suspicious_activity" => Ok(SecurityEventType::SuspiciousActivity),
            
            "session_created" => Ok(SecurityEventType::SessionCreated),
            "session_expired" => Ok(SecurityEventType::SessionExpired),
            "session_deleted" => Ok(SecurityEventType::SessionDeleted),
            "credential_created" => Ok(SecurityEventType::CredentialCreated),
            "credential_updated" => Ok(SecurityEventType::CredentialUpdated),
            "credential_deleted" => Ok(SecurityEventType::CredentialDeleted),
            
            _ => Err(AppError::Internal(format!("Unknown event type: {}", event_type))),
        }
    }

    /// Determine severity based on event type and success
    fn determine_severity(&self, event_type: &SecurityEventType, success: bool) -> AuditSeverity {
        match event_type {
            SecurityEventType::ReplayAttackDetected => AuditSeverity::Critical,
            SecurityEventType::AuthenticationCredentialMismatch => AuditSeverity::Error,
            SecurityEventType::InvalidSessionState => AuditSeverity::Error,
            SecurityEventType::RateLimitExceeded => AuditSeverity::Warning,
            SecurityEventType::SuspiciousActivity => AuditSeverity::Warning,
            
            SecurityEventType::RegistrationFailed | SecurityEventType::AuthenticationFailed => {
                if success {
                    AuditSeverity::Info
                } else {
                    AuditSeverity::Warning
                }
            }
            
            _ => {
                if success {
                    AuditSeverity::Info
                } else {
                    AuditSeverity::Error
                }
            }
        }
    }

    /// Log to console (in production, use proper audit log storage)
    fn log_to_console(&self, entry: &AuditLogEntry) {
        let log_level = match entry.severity {
            AuditSeverity::Info => "INFO",
            AuditSeverity::Warning => "WARN",
            AuditSeverity::Error => "ERROR",
            AuditSeverity::Critical => "CRITICAL",
        };

        let details_json = entry.details
            .as_ref()
            .map(|d| serde_json::to_string(d).unwrap_or_default())
            .unwrap_or_default();

        log::info!(
            target: "audit",
            "[{}] {} - User: {}, IP: {}, Event: {:?}, Success: {}, Details: {}",
            log_level,
            entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
            entry.username.as_deref().unwrap_or("unknown"),
            entry.client_ip.as_deref().unwrap_or("unknown"),
            entry.event_type,
            entry.success,
            details_json
        );
    }
}

#[async_trait::async_trait]
impl AuditLogger for DefaultAuditLogger {
    async fn log_security_event(
        &self,
        event_type: &str,
        username: Option<&str>,
        client_ip: Option<&str>,
        details: Option<Value>,
    ) -> Result<()> {
        let entry = self.create_audit_entry(event_type, username, client_ip, details, true, None)?;
        self.log_to_console(&entry);
        
        // In production, store to audit database
        Ok(())
    }

    async fn log_audit_entry(&self, entry: AuditLogEntry) -> Result<()> {
        self.log_to_console(&entry);
        
        // In production, store to audit database
        Ok(())
    }

    async fn search_audit_logs(
        &self,
        _filters: AuditLogFilters,
    ) -> Result<Vec<AuditLogEntry>> {
        // In production, query audit database
        // For now, return empty results
        Ok(vec![])
    }
}

/// Security event builder for structured logging
pub struct SecurityEventBuilder {
    event_type: String,
    username: Option<String>,
    client_ip: Option<String>,
    details: HashMap<String, Value>,
    success: bool,
    error_message: Option<String>,
}

impl SecurityEventBuilder {
    pub fn new(event_type: impl Into<String>) -> Self {
        Self {
            event_type: event_type.into(),
            username: None,
            client_ip: None,
            details: HashMap::new(),
            success: true,
            error_message: None,
        }
    }

    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    pub fn client_ip(mut self, client_ip: impl Into<String>) -> Self {
        self.client_ip = Some(client_ip.into());
        self
    }

    pub fn detail(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn error(mut self, error: impl Into<String>) -> Self {
        self.success = false;
        self.error_message = Some(error.into());
        self
    }

    pub fn build(self) -> (String, Option<String>, Option<String>, Option<Value>) {
        let details = if self.details.is_empty() {
            None
        } else {
            Some(Value::Object(self.details.into_iter().collect()))
        };

        (
            self.event_type,
            self.username,
            self.client_ip,
            details,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_security_event_logging() {
        let audit_logger = DefaultAuditLogger::new();

        let event = SecurityEventBuilder::new("registration_start_attempt")
            .username("test@example.com")
            .client_ip("192.168.1.1")
            .detail("user_verification", "required")
            .detail("attestation_preference", "direct")
            .build();

        audit_logger.log_security_event(event.0, event.1.as_deref(), event.2.as_deref(), event.3).await.unwrap();
    }

    #[test]
    fn test_security_event_builder() {
        let event = SecurityEventBuilder::new("authentication_failed")
            .username("test@example.com")
            .client_ip("192.168.1.1")
            .detail("credential_id", "test_credential_id")
            .detail("reason", "invalid_signature")
            .success(false)
            .error("Invalid signature")
            .build();

        assert_eq!(event.0, "authentication_failed");
        assert_eq!(event.1, Some("test@example.com".to_string()));
        assert_eq!(event.2, Some("192.168.1.1".to_string()));
        
        let details = event.3.unwrap();
        assert_eq!(details["credential_id"], "test_credential_id");
        assert_eq!(details["reason"], "invalid_signature");
    }

    #[test]
    fn test_severity_determination() {
        let audit_logger = DefaultAuditLogger::new();

        let critical_severity = audit_logger.determine_severity(
            &SecurityEventType::ReplayAttackDetected,
            false
        );
        assert_eq!(critical_severity, AuditSeverity::Critical);

        let info_severity = audit_logger.determine_severity(
            &SecurityEventType::RegistrationCompleted,
            true
        );
        assert_eq!(info_severity, AuditSeverity::Info);

        let warning_severity = audit_logger.determine_severity(
            &SecurityEventType::AuthenticationFailed,
            false
        );
        assert_eq!(warning_severity, AuditSeverity::Warning);
    }
}