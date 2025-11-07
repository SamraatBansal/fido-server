use actix_web::{HttpResponse, Result};
use serde_json::json;

pub async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "version": "0.1.0"
    })))
}