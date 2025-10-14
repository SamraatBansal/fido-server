//! Service layer for business logic

use async_trait::async_trait;
use crate::controllers::dto::*;
use crate::error::Result;

#[async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn begin_registration(&self, request: ServerPublicKeyCredentialCreationOptionsRequest) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;
    async fn finish_registration(&self, credential: ServerPublicKeyCredential) -> Result<ServerResponse>;
    async fn begin_authentication(&self, request: ServerPublicKeyCredentialGetOptionsRequest) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;
    async fn finish_authentication(&self, credential: ServerPublicKeyCredential) -> Result<ServerResponse>;
}

pub mod webauthn_service;
pub mod challenge_service;
pub mod crypto_service;

pub use webauthn_service::WebAuthnServiceImpl;
pub use challenge_service::ChallengeService;
pub use crypto_service::CryptoService;