//! Common test helper functions and utilities

use actix_web::{dev::ServiceResponse, http::StatusCode, test, App};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

/// Test application context
pub struct TestApp {
    pub app: actix_web::app::App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    >,
    pub temp_dir: TempDir,
}

impl TestApp {
    /// Create a new test application instance
    pub fn new() -> Self {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        
        // This would be replaced with actual app configuration
        let app = test::init_service(
            App::new().configure(fido_server::routes::configure_routes),
        );
        
        Self { app, temp_dir }
    }
}

/// HTTP test helper
pub struct HttpTestHelper;

impl HttpTestHelper {
    /// Make a POST request with JSON body
    pub async fn post_json(
        app: &actix_web::app::App<impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >>,
        path: &str,
        body: &Value,
    ) -> ServiceResponse {
        let req = test::TestRequest::post()
            .uri(path)
            .set_json(body)
            .to_request();
        
        test::call_service(app, req).await
    }

    /// Make a GET request
    pub async fn get(
        app: &actix_web::app::App<impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >>,
        path: &str,
    ) -> ServiceResponse {
        let req = test::TestRequest::get().uri(path).to_request();
        test::call_service(app, req).await
    }

    /// Extract response body as JSON
    pub async fn response_json<T: serde::de::DeserializeOwned>(
        response: ServiceResponse,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let body = test::read_body(response).await;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Extract response body as text
    pub async fn response_text(response: ServiceResponse) -> String {
        let body = test::read_body(response).await;
        String::from_utf8_lossy(&body).to_string()
    }
}

/// Assertion helpers for testing
pub struct AssertionHelper;

impl AssertionHelper {
    /// Assert response status code
    pub fn assert_status(response: &ServiceResponse, expected: StatusCode) {
        assert_eq!(
            response.status(),
            expected,
            "Expected status {}, got {}",
            expected,
            response.status()
        );
    }

    /// Assert response contains required fields
    pub fn assert_contains_fields(response: &Value, fields: &[&str]) {
        for field in fields {
            assert!(
                response.get(field).is_some(),
                "Response missing required field: {}",
                field
            );
        }
    }

    /// Assert field is valid base64url
    pub fn assert_base64url(value: &str) {
        URL_SAFE_NO_PAD
            .decode(value)
            .unwrap_or_else(|_| panic!("Invalid base64url string: {}", value));
    }

    /// Assert challenge is properly formatted
    pub fn assert_challenge_format(challenge: &str) {
        assert!(!challenge.is_empty(), "Challenge should not be empty");
        assert!(
            challenge.len() >= 16,
            "Challenge should be at least 16 characters"
        );
        Self::assert_base64url(challenge);
    }

    /// Assert credential ID is properly formatted
    pub fn assert_credential_id_format(credential_id: &str) {
        assert!(!credential_id.is_empty(), "Credential ID should not be empty");
        Self::assert_base64url(credential_id);
    }

    /// Assert client data JSON structure
    pub fn assert_client_data_structure(client_data: &Value) {
        assert!(
            client_data.get("type").is_some(),
            "Client data missing 'type' field"
        );
        assert!(
            client_data.get("challenge").is_some(),
            "Client data missing 'challenge' field"
        );
        assert!(
            client_data.get("origin").is_some(),
            "Client data missing 'origin' field"
        );
    }

    /// Assert attestation options response structure
    pub fn assert_attestation_options_structure(response: &Value) {
        let required_fields = [
            "challenge",
            "rp",
            "user",
            "pubKeyCredParams",
            "timeout",
            "attestation",
        ];
        Self::assert_contains_fields(response, &required_fields);

        // Check RP structure
        let rp = response.get("rp").unwrap();
        Self::assert_contains_fields(rp, &["name", "id"]);

        // Check user structure
        let user = response.get("user").unwrap();
        Self::assert_contains_fields(user, &["id", "name", "displayName"]);

        // Check pubKeyCredParams is an array
        assert!(
            response.get("pubKeyCredParams").unwrap().as_array().is_some(),
            "pubKeyCredParams should be an array"
        );
    }

    /// Assert assertion options response structure
    pub fn assert_assertion_options_structure(response: &Value) {
        let required_fields = ["challenge", "rpId", "allowCredentials", "timeout"];
        Self::assert_contains_fields(response, &required_fields);

        // Check allowCredentials is an array
        assert!(
            response.get("allowCredentials").unwrap().as_array().is_some(),
            "allowCredentials should be an array"
        );
    }

    /// Assert attestation result request structure
    pub fn assert_attestation_result_structure(request: &Value) {
        let required_fields = ["id", "rawId", "response", "type"];
        Self::assert_contains_fields(request, &required_fields);

        // Check response structure
        let response = request.get("response").unwrap();
        Self::assert_contains_fields(response, &["attestationObject", "clientDataJSON"]);

        // Check type is "public-key"
        assert_eq!(
            request.get("type").unwrap().as_str().unwrap(),
            "public-key",
            "Type should be 'public-key'"
        );
    }

    /// Assert assertion result request structure
    pub fn assert_assertion_result_structure(request: &Value) {
        let required_fields = ["id", "rawId", "response", "type"];
        Self::assert_contains_fields(request, &required_fields);

        // Check response structure
        let response = request.get("response").unwrap();
        Self::assert_contains_fields(
            response,
            &["authenticatorData", "clientDataJSON", "signature"],
        );

        // Check type is "public-key"
        assert_eq!(
            request.get("type").unwrap().as_str().unwrap(),
            "public-key",
            "Type should be 'public-key'"
        );
    }
}

/// Timing helper for performance testing
pub struct TimingHelper;

impl TimingHelper {
    /// Measure execution time of a function
    pub async fn measure_time<F, Fut, T>(f: F) -> (T, Duration)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let start = std::time::Instant::now();
        let result = f().await;
        let duration = start.elapsed();
        (result, duration)
    }

    /// Assert execution time is within bounds
    pub fn assert_duration_within(duration: Duration, min: Duration, max: Duration) {
        assert!(
            duration >= min,
            "Duration {:?} is less than minimum {:?}",
            duration,
            min
        );
        assert!(
            duration <= max,
            "Duration {:?} exceeds maximum {:?}",
            duration,
            max
        );
    }
}

/// Database helper for testing
pub struct DatabaseHelper;

impl DatabaseHelper {
    /// Create test database configuration
    pub fn test_config() -> HashMap<String, String> {
        let mut config = HashMap::new();
        config.insert("database_url".to_string(), "postgresql://test:test@localhost:5432/fido_test".to_string());
        config.insert("max_connections".to_string(), "5".to_string());
        config.insert("min_connections".to_string(), "1".to_string());
        config.insert("connection_timeout".to_string(), "30".to_string());
        config
    }

    /// Clean up test database
    pub async fn cleanup_test_db() -> Result<(), Box<dyn std::error::Error>> {
        // This would implement actual database cleanup
        // For now, just return Ok
        Ok(())
    }

    /// Seed test data
    pub async fn seed_test_data() -> Result<(), Box<dyn std::error::Error>> {
        // This would implement actual test data seeding
        // For now, just return Ok
        Ok(())
    }
}

/// Security test helper
pub struct SecurityTestHelper;

impl SecurityTestHelper {
    /// Generate random challenge for testing
    pub fn generate_challenge() -> String {
        let challenge: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        URL_SAFE_NO_PAD.encode(challenge)
    }

    /// Generate mock attestation object
    pub fn mock_attestation_object() -> Vec<u8> {
        // This would generate a proper CBOR-encoded attestation object
        // For now, return mock data
        b"mock_attestation_object".to_vec()
    }

    /// Generate mock authenticator data
    pub fn mock_authenticator_data() -> Vec<u8> {
        // This would generate proper authenticator data
        // For now, return mock data
        b"mock_authenticator_data".to_vec()
    }

    /// Generate mock signature
    pub fn mock_signature() -> Vec<u8> {
        // This would generate a proper signature
        // For now, return mock data
        b"mock_signature".to_vec()
    }

    /// Tamper with data for security testing
    pub fn tamper_data(data: &[u8], tamper_type: &str) -> Vec<u8> {
        let mut tampered = data.to_vec();
        match tamper_type {
            "flip_bit" => {
                if !tampered.is_empty() {
                    tampered[0] ^= 0x01;
                }
            }
            "truncate" => {
                tampered.truncate(tampered.len() / 2);
            }
            "append" => {
                tampered.extend_from_slice(b"tampered");
            }
            _ => {}
        }
        tampered
    }
}

/// Mock service helper for testing
pub struct MockServiceHelper;

impl MockServiceHelper {
    /// Create mock WebAuthn service
    pub fn create_mock_webauthn_service() -> Box<dyn fido_server::services::WebAuthnService> {
        // This would create a mock implementation
        // For now, panic to indicate implementation needed
        panic!("Mock WebAuthn service implementation needed")
    }

    /// Create mock credential service
    pub fn create_mock_credential_service() -> Box<dyn fido_server::services::CredentialService> {
        // This would create a mock implementation
        // For now, panic to indicate implementation needed
        panic!("Mock credential service implementation needed")
    }

    /// Create mock user service
    pub fn create_mock_user_service() -> Box<dyn fido_server::services::UserService> {
        // This would create a mock implementation
        // For now, panic to indicate implementation needed
        panic!("Mock user service implementation needed")
    }
}

/// Configuration helper for testing
pub struct ConfigHelper;

impl ConfigHelper {
    /// Load test configuration
    pub fn load_test_config() -> HashMap<String, String> {
        let mut config = HashMap::new();
        
        // WebAuthn config
        config.insert("rp_name".to_string(), "Test RP".to_string());
        config.insert("rp_id".to_string(), "localhost".to_string());
        config.insert("rp_origin".to_string(), "http://localhost:8080".to_string());
        config.insert("challenge_timeout_seconds".to_string(), "300".to_string());
        
        // Database config
        config.insert("database_url".to_string(), "postgresql://test:test@localhost:5432/fido_test".to_string());
        
        // Security config
        config.insert("rate_limit_requests_per_minute".to_string(), "100".to_string());
        config.insert("max_request_size_bytes".to_string(), "1048576".to_string()); // 1MB
        
        config
    }

    /// Create environment variables for testing
    pub fn setup_test_env() {
        std::env::set_var("RUST_LOG", "debug");
        std::env::set_var("DATABASE_URL", "postgresql://test:test@localhost:5432/fido_test");
        std::env::set_var("RP_ID", "localhost");
        std::env::set_var("RP_ORIGIN", "http://localhost:8080");
    }

    /// Clean up test environment
    pub fn cleanup_test_env() {
        std::env::remove_var("RUST_LOG");
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("RP_ID");
        std::env::remove_var("RP_ORIGIN");
    }
}