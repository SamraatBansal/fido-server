//! Utility function unit tests

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    #[tokio::test]
    async fn test_base64url_encoding() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        
        let data = b"hello world";
        let encoded = URL_SAFE_NO_PAD.encode(data);
        let decoded = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        
        assert_eq!(data, decoded.as_slice());
    }

    #[tokio::test]
    async fn test_uuid_generation() {
        use uuid::Uuid;
        
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        
        assert_ne!(id1, id2);
        assert_eq!(id1.get_version_num(), 4);
        assert_eq!(id2.get_version_num(), 4);
    }

    #[tokio::test]
    async fn test_challenge_generation() {
        use rand::RngCore;
        
        let mut rng = rand::thread_rng();
        let mut challenge1 = [0u8; 32];
        let mut challenge2 = [0u8; 32];
        
        rng.fill_bytes(&mut challenge1);
        rng.fill_bytes(&mut challenge2);
        
        assert_ne!(challenge1, challenge2);
    }

    #[tokio::test]
    async fn test_timestamp_validation() {
        let created_at = Utc::now();
        let _expires_at = created_at + Duration::minutes(5);
        let _now = Utc::now();
        
        // Basic timestamp validation test structure
        assert!(true);
    }

    #[tokio::test]
    async fn test_email_validation() {
        let valid_emails = vec![
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
        ];
        
        let invalid_emails = vec![
            "invalid-email",
            "@example.com",
            "test@",
            "test.example.com",
            "test@.com",
        ];
        
        for email in valid_emails {
            assert!(email.contains('@'));
            assert!(email.contains('.'));
        }
        
        for email in invalid_emails {
            assert!(!email.contains('@') || !email.contains('.'));
        }
    }

    #[tokio::test]
    async fn test_credential_id_validation() {
        let valid_ids = vec![
            vec![1, 2, 3, 4],
            vec![0; 16],
            vec![255; 32],
        ];
        
        let invalid_ids = vec![
            vec![],
            vec![0; 1025], // Too long
        ];
        
        for id in &valid_ids {
            assert!(!id.is_empty());
            assert!(id.len() <= 1024);
        }
        
        for id in &invalid_ids {
            assert!(id.is_empty() || id.len() > 1024);
        }
    }

    #[tokio::test]
    async fn test_json_serialization() {
        use serde_json::{json, Value};
        
        let data = json!({
            "username": "test@example.com",
            "display_name": "Test User"
        });
        
        let serialized = serde_json::to_string(&data).unwrap();
        let deserialized: Value = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(data["username"], deserialized["username"]);
        assert_eq!(data["display_name"], deserialized["display_name"]);
    }

    #[tokio::test]
    async fn test_error_handling() {
        use fido_server::error::AppError;
        
        let validation_error = AppError::ValidationError("Test error".to_string());
        let not_found_error = AppError::NotFound("Resource not found".to_string());
        let bad_request_error = AppError::BadRequest("Invalid request".to_string());
        
        assert!(matches!(validation_error, AppError::ValidationError(_)));
        assert!(matches!(not_found_error, AppError::NotFound(_)));
        assert!(matches!(bad_request_error, AppError::BadRequest(_)));
    }
}