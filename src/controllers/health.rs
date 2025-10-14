use actix_web::{web, HttpResponse, Result};
use serde_json::json;

pub async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "fido-server",
        "version": env!("CARGO_PKG_VERSION")
    })))
}