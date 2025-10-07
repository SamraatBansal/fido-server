use fido_server::{
    config::AppConfig,
    utils::{generate_challenge, hash_data, verify_hash},
};

#[tokio::test]
async fn test_challenge_generation() {
    let challenge1 = generate_challenge();
    let challenge2 = generate_challenge();

    // Challenges should be different
    assert_ne!(challenge1, challenge2);

    // Challenges should be base64url encoded
    assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&challenge1).is_ok());
    assert!(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&challenge2).is_ok());
}

#[tokio::test]
async fn test_hash_verification() {
    let data = b"test data";
    let hash = hash_data(data);

    // Verify the hash
    assert!(verify_hash(data, &hash));

    // Verify with wrong data
    assert!(!verify_hash(b"wrong data", &hash));
}

#[tokio::test]
async fn test_config_loading() {
    // Test default configuration
    let config = AppConfig::default();
    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 8080);
    assert_eq!(config.webauthn.rp_id, "localhost");
}

#[tokio::test]
async fn test_error_handling() {
    use fido_server::error::{AppError, Result};

    // Test error creation
    let error = AppError::UserNotFound;
    assert!(matches!(error, AppError::UserNotFound));

    let result: Result<()> = Err(AppError::InvalidRequest("test".to_string()));
    assert!(result.is_err());
}