//! Custom error handlers for actix-web

use actix_web::{error::JsonPayloadError, HttpResponse};
use crate::types::ServerResponse;

/// Handle JSON payload errors and return proper JSON responses
pub fn handle_json_payload_error(err: JsonPayloadError, _req: &actix_web::HttpRequest) -> actix_web::Error {
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
    
    actix_web::error::InternalError::from_response(
        err,
        HttpResponse::BadRequest().json(error_response),
    ).into()
}