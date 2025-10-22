//! Error handling middleware for JSON deserialization errors

use actix_web::{error::JsonPayloadError, error::ResponseError, http::StatusCode, HttpResponse, Result};
use crate::models::dto::ServerResponse;

impl ResponseError for JsonPayloadError {
    fn error_response(&self) -> HttpResponse {
        let (status, message) = match self {
            JsonPayloadError::Deserialize(err) => {
                (StatusCode::BAD_REQUEST, format!("Invalid request format: {}", err))
            }
            JsonPayloadError::ContentType => {
                (StatusCode::BAD_REQUEST, "Invalid content type".to_string())
            }
            JsonPayloadError::Payload(err) => {
                (StatusCode::BAD_REQUEST, format!("Invalid payload: {}", err))
            }
            _ => {
                (StatusCode::BAD_REQUEST, "Invalid JSON request".to_string())
            }
        };

        HttpResponse::build(status).json(ServerResponse::error(message))
    }
}