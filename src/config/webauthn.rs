//! WebAuthn configuration

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs_proto::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub attestation_preference: AttestationConveyancePreference,
    pub user_verification: UserVerificationPolicy,
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub resident_key: ResidentKeyRequirement,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "FIDO Server".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            attestation_preference: AttestationConveyancePreference::Direct,
            user_verification: UserVerificationPolicy::Preferred,
            authenticator_attachment: None,
            resident_key: ResidentKeyRequirement::Discouraged,
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters::Ec2 {
                    curve: Ec2Curve::ES256,
                },
                PublicKeyCredentialParameters::Rsa {
                    modulus_length: 2048,
                    padding: RsaSignaturePadding::Pkcs1v15Sha256,
                },
                PublicKeyCredentialParameters::EdDSA {
                    curve: EdDSACurve::Ed25519,
                },
            ],
        }
    }
}

impl WebAuthnConfig {
    pub fn build_webauthn(&self) -> Result<Webauthn> {
        let rp_id = RpId::from_str(&self.rp_id)
            .map_err(|e| crate::error::AppError::InvalidRequest(format!("Invalid RP ID: {}", e)))?;
        
        let rp_origin = Url::parse(&self.rp_origin)
            .map_err(|e| crate::error::AppError::InvalidRequest(format!("Invalid origin: {}", e)))?;

        let webauthn = WebAuthn::new(
            rp_id,
            self.rp_name.clone(),
            rp_origin,
        );

        Ok(webauthn)
    }

    pub fn build_registration_options(&self, user: User) -> Result<CreationChallengeResponse> {
        let webauthn = self.build_webauthn()?;
        
        let (ccr, reg_state) = webauthn
            .start_registration(&user, self.authenticator_attachment, self.user_verification, self.resident_key, None, Some(self.attestation_preference))
            .map_err(crate::error::AppError::WebAuthn)?;

        Ok(ccr)
    }

    pub fn build_authentication_options(&self, allowed_creds: Vec<PublicKeyCredentialDescriptor>) -> Result<RequestChallengeResponse> {
        let webauthn = self.build_webauthn()?;
        
        let (acr, auth_state) = webauthn
            .start_authentication(&allowed_creds, Some(self.user_verification))
            .map_err(crate::error::AppError::WebAuthn)?;

        Ok(acr)
    }
}