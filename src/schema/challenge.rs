//! Challenge schema types

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeData {
    pub data: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub operation: ChallengeOperation,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ChallengeOperation {
    Registration,
    Authentication,
}

impl std::fmt::Display for ChallengeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Registration => write!(f, "registration"),
            Self::Authentication => write!(f, "authentication"),
        }
    }
}