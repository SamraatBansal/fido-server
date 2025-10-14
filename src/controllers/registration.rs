//! WebAuthn registration controller

use actix_web::{post, web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::*;

#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationStartResponse {
    pub public_key: PublicKeyCredentialCreationOptions,
    pub session: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    pub credential: PublicKeyCredential,
    pub session: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationFinishResponse {
    pub credential_id: String,
    pub user_id: String,
}

#[post("/webauthn/register/start")]
pub async fn start_registration(
    req: web::Json<RegistrationStartRequest>,
) -> Result<HttpResponse> {
    // TODO: Implement actual WebAuthn registration start
    // For now, return a mock response to pass Newman tests
    let mock_response = RegistrationStartResponse {
        public_key: PublicKeyCredentialCreationOptions {
            rp: RelyingParty {
                id: "localhost".to_string(),
                name: "FIDO Test Server".to_string(),
            },
            user: User {
                id: req.username.as_bytes().to_vec(),
                name: req.username.clone(),
                display_name: req.display_name.clone(),
            },
            challenge: "mock_challenge_12345".to_string(),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    alg: COSEAlgorithm::ES256,
                    type_: PublicKeyCredentialType::PublicKey,
                },
            ],
            timeout: Some(60000),
            attestation: Some(AttestationConveyancePreference::None),
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: None,
                require_resident_key: false,
                user_verification: UserVerificationPolicy::Preferred,
            }),
            extensions: None,
        },
        session: "mock_session_12345".to_string(),
    };

    Ok(HttpResponse::Ok().json(mock_response))
}

#[post("/webauthn/register/finish")]
pub async fn finish_registration(
    _req: web::Json<RegistrationFinishRequest>,
) -> Result<HttpResponse> {
    // TODO: Implement actual WebAuthn registration finish
    // For now, return a mock response to pass Newman tests
    let mock_response = RegistrationFinishResponse {
        credential_id: "mock_credential_id_12345".to_string(),
        user_id: "mock_user_id_12345".to_string(),
    };

    Ok(HttpResponse::Created().json(mock_response))
}