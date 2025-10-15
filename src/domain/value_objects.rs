//! Value objects for the FIDO2 server

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// User ID value object
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for UserId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<UserId> for Uuid {
    fn from(user_id: UserId) -> Self {
        user_id.0
    }
}

/// Credential ID value object
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CredentialId(pub Vec<u8>);

impl CredentialId {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64url(&self) -> String {
        base64urlsafedata::Base64UrlSafeData::from(&self.0).to_string()
    }

    pub fn from_base64url(s: &str) -> Result<Self, base64urlsafedata::Base64UrlSafeDataError> {
        let data = base64urlsafedata::Base64UrlSafeData::try_from(s)?;
        Ok(Self(data.into()))
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64url())
    }
}

/// Challenge value object
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeValue(pub Vec<u8>);

impl ChallengeValue {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut challenge = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut challenge);
        Self(challenge)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_base64url(&self) -> String {
        base64urlsafedata::Base64UrlSafeData::from(&self.0).to_string()
    }

    pub fn from_base64url(s: &str) -> Result<Self, base64urlsafedata::Base64UrlSafeDataError> {
        let data = base64urlsafedata::Base64UrlSafeData::try_from(s)?;
        Ok(Self(data.into()))
    }
}

impl fmt::Display for ChallengeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64url())
    }
}

/// Username value object with validation
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Username(String);

impl Username {
    pub fn new(username: String) -> Result<Self, crate::error::AppError> {
        if username.is_empty() {
            return Err(crate::error::AppError::ValidationError(
                "Username cannot be empty".to_string(),
            ));
        }

        if username.len() > 255 {
            return Err(crate::error::AppError::ValidationError(
                "Username too long".to_string(),
            ));
        }

        // Basic email validation
        if !username.contains('@') {
            return Err(crate::error::AppError::ValidationError(
                "Username must be a valid email".to_string(),
            ));
        }

        Ok(Self(username))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for Username {
    type Error = crate::error::AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Username> for String {
    fn from(username: Username) -> Self {
        username.0
    }
}