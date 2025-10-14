//! Error handling middleware

use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    error::JsonPayloadError,
    middleware::ErrorHandlerResponse,
    HttpResponse, Result,
};
use serde_json::json;

/// Handle JSON payload errors and return proper JSON error responses
pub fn json_error_handler<B>(
    res: ServiceResponse<B>,
) -> Result<ErrorHandlerResponse<B>> {
    let (req, res) = res.into_parts();
    
    // Create a JSON error response
    let error_response = HttpResponse::BadRequest().json(json!({
        "status": "failed",
        "errorMessage": "Invalid JSON payload"
    }));

    let (res, _body) = error_response.into_parts();
    let res = ServiceResponse::new(req, res.map_body(|_head, _body| B::default()));
    
    Ok(ErrorHandlerResponse::Response(res))
}