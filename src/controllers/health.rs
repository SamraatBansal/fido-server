//! Health check controller

use actix_web::{HttpResponse, Result as ActixResult};
use serde_json::json;

pub async fn health_check() -> ActixResult<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}