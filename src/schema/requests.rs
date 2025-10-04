//! Request DTOs

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RegistrationFinishRequest {
    pub credential: PublicKeyCredential,
    pub session_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthenticationFinishRequest {
    pub credential: PublicKeyCredential,
    pub session_id: String,
}