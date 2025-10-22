//! Error handling utilities for JSON errors

use actix_web::{error::JsonPayloadError, HttpResponse};
use crate::models::dto::ServerResponse;

// Helper function to create a proper error response for JSON errors
pub fn handle_json_error(error: &JsonPayloadError) -> HttpResponse {
    let message = match error {
        JsonPayloadError::Deserialize(err) => {
            format!("Invalid request format: {}", err)
        }
        JsonPayloadError::ContentType => {
            "Invalid content type".to_string()
        }
        JsonPayloadError::Payload(err) => {
            format!("Invalid payload: {}", err)
        }
        _ => {
            "Invalid JSON request".to_string()
        }
    };

    HttpResponse::BadRequest().json(ServerResponse::error(message))
}