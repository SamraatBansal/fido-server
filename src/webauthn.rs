use crate::config::Config;
use crate::error::AppError;
use webauthn_rs::prelude::*;

pub type WebAuthnInstance = WebAuthn<WebauthnConfig>;

pub fn create_webauthn_instance(config: &Config) -> Result<WebAuthnInstance, AppError> {
    let rp_config = RpConfig {
        rp_id: config.rp_id.clone(),
        rp_name: config.rp_name.clone(),
        rp_origin: Url::parse(&config.rp_origin)
            .map_err(|e| AppError::Internal(format!("Invalid RP origin: {}", e)))?,
    };

    let webauthn_config = WebauthnConfig {
        rp: rp_config,
        // Enable all supported algorithms for maximum compatibility
        algorithms: vec![
            COSEAlgorithm::ES256,
            COSEAlgorithm::RS256,
            COSEAlgorithm::EdDSA,
        ],
        // Require user verification for security
        user_verification: UserVerificationPolicy::Required,
        // Enable resident key support
        resident_key_requirement: ResidentKeyRequirement::Preferred,
        // Set timeout to 5 minutes
        timeout: Some(300),
        // Enable attestation for security
        attestation: AttestationConveyancePreference::Direct,
    };

    Ok(WebAuthn::new(webauthn_config))
}

pub fn generate_user_id(username: &str) -> UserId {
    UserId::from_bytes(username.as_bytes().to_vec())
}

pub fn create_user_data(username: &str, display_name: &str) -> UserData {
    UserData::new(
        generate_user_id(username),
        username.to_string(),
        display_name.to_string(),
        None,
    )
}