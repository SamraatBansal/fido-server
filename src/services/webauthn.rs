//! WebAuthn service implementation

use base64::Engine;
use rand::Rng;

/// WebAuthn service for handling FIDO2 authentication
pub struct WebAuthnService {
    rp_id: String,
    rp_name: String,
    rp_origin: String,
}

impl WebAuthnService {
    /// Creates a new WebAuthn service instance
    pub fn new(rp_id: &str, rp_origin: &str) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            rp_name: "FIDO Server".to_string(),
            rp_origin: rp_origin.to_string(),
        }
    }

    /// Generates a random challenge for WebAuthn authentication
    pub fn generate_challenge(&self) -> String {
        let mut rng = rand::thread_rng();
        let challenge: [u8; 32] = rng.gen();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    }

    /// Gets the relying party ID
    pub fn get_rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Gets the relying party name
    pub fn get_rp_name(&self) -> &str {
        &self.rp_name
    }

    /// Gets the relying party origin
    pub fn get_rp_origin(&self) -> &str {
        &self.rp_origin
    }
}