//! Custom error handlers for actix-web

use actix_web::{error::JsonPayloadError, HttpResponse, Result};
use crate::error::{AppError, ServerResponse};

/// Handle JSON payload errors and return proper JSON responses
pub fn handle_json_payload_error(err: JsonPayloadError, _req: &actix_web::HttpRequest) -> Result<HttpResponse> {
    let error_response = match err {
        JsonPayloadError::Deserialize(_) => {
            ServerResponse::error("Invalid JSON format")
        },
        JsonPayloadError::ContentType => {
            ServerResponse::error("Content-Type must be application/json")
        },
        JsonPayloadError::Payload(_) => {
            ServerResponse::error("Invalid request payload")
        },
        _ => {
            ServerResponse::error("Request parsing error")
        }
    };
    
    Ok(HttpResponse::BadRequest().json(error_response))
}