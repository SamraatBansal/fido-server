//! Error handling middleware (simplified)

use actix_web::{dev::ServiceRequest, Error as ActixError};
use tracing::{error, warn};

use crate::error::AppError;

/// Error handling middleware
pub struct ErrorHandler;

impl ErrorHandler {
    pub fn log_error(req: &ServiceRequest, error: &ActixError) {
        let path = req.path();
        let method = req.method();

        match error.as_error::<AppError>() {
            Some(app_error) => {
                match app_error {
                    AppError::ValidationError(msg) => {
                        warn!("Validation error on {} {}: {}", method, path, msg);
                    }
                    AppError::BadRequest(msg) => {
                        warn!("Bad request on {} {}: {}", method, path, msg);
                    }
                    AppError::NotFound(msg) => {
                        warn!("Not found on {} {}: {}", method, path, msg);
                    }
                    AppError::Unauthorized(msg) => {
                        warn!("Unauthorized on {} {}: {}", method, path, msg);
                    }
                    AppError::RateLimitExceeded(msg) => {
                        warn!("Rate limit exceeded on {} {}: {}", method, path, msg);
                    }
                    AppError::WebAuthnError(msg) => {
                        warn!("WebAuthn error on {} {}: {}", method, path, msg);
                    }
                    AppError::DatabaseError(msg) => {
                        error!("Database error on {} {}: {}", method, path, msg);
                    }
                    AppError::InternalError(msg) => {
                        error!("Internal error on {} {}: {}", method, path, msg);
                    }
                    AppError::ChallengeExpired(msg) => {
                        warn!("Challenge expired on {} {}: {}", method, path, msg);
                    }
                    AppError::InvalidChallenge(msg) => {
                        warn!("Invalid challenge on {} {}: {}", method, path, msg);
                    }
                    AppError::CredentialAlreadyExists(msg) => {
                        warn!("Credential already exists on {} {}: {}", method, path, msg);
                    }
                    AppError::InvalidSignature(msg) => {
                        warn!("Invalid signature on {} {}: {}", method, path, msg);
                    }
                }
            }
            None => {
                error!("Unexpected error on {} {}: {}", method, path, error);
            }
        }
    }
}