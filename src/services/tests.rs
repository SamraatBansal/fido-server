#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::WebAuthnService;
    use crate::config::{WebAuthnConfig, AppConfig};
    use crate::db::mock_repositories::{MockUserRepository, MockCredentialRepository, MockAuthSessionRepository, MockAuditLogRepository};
    use crate::schema::{AttestationOptionsRequest, RequestContext};
    use std::sync::Arc;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_webauthn_service_creation() {
        let config = WebAuthnConfig {
            rp_id: "localhost".to_string(),
            rp_name: "Test Server".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: 60000,
            attestation_preference: "direct".to_string(),
            user_verification: "preferred".to_string(),
        };

        let user_repo = Arc::new(MockUserRepository::new());
        let credential_repo = Arc::new(MockCredentialRepository::new());
        let session_repo = Arc::new(MockAuthSessionRepository::new());
        let audit_repo = Arc::new(MockAuditLogRepository::new());

        let service = WebAuthnService::new(
            config,
            user_repo,
            credential_repo,
            session_repo,
            audit_repo,
        );

        assert!(service.is_ok());
    }

    #[tokio::test]
    async fn test_attestation_start_request_validation() {
        let request = AttestationOptionsRequest {
            username: "testuser".to_string(),
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
            extensions: None,
            user_verification: None,
        };

        assert!(request.validate().is_ok());
    }

    #[tokio::test]
    async fn test_attestation_start_invalid_request() {
        let request = AttestationOptionsRequest {
            username: "".to_string(), // Invalid: empty username
            display_name: "Test User".to_string(),
            authenticator_selection: None,
            attestation: None,
            extensions: None,
            user_verification: None,
        };

        assert!(request.validate().is_err());
    }

    #[tokio::test]
    async fn test_request_context_creation() {
        let context = RequestContext {
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            session_id: None,
        };

        assert_eq!(context.ip_address, Some("127.0.0.1".to_string()));
        assert_eq!(context.user_agent, Some("Mozilla/5.0".to_string()));
        assert!(context.session_id.is_none());
    }

    #[tokio::test]
    async fn test_uuid_handling() {
        let user_id = Uuid::new_v4();
        let user_id_str = user_id.to_string();
        
        // Test UUID parsing
        let parsed = Uuid::parse_str(&user_id_str);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap(), user_id);
    }

    #[tokio::test]
    async fn test_config_defaults() {
        let config = AppConfig::default();
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.webauthn.rp_id, "localhost");
    }

    #[tokio::test]
    async fn test_error_handling() {
        use crate::error::{AppError, Result};

        // Test error creation
        let error = AppError::UserNotFound;
        assert!(matches!(error, AppError::UserNotFound));

        let result: Result<()> = Err(AppError::InvalidRequest("test".to_string()));
        assert!(result.is_err());
    }
}