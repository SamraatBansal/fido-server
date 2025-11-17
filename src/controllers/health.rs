use actix_web::{web, HttpResponse, Result};
use serde_json::json;

#[actix_web::get("/health")]
pub async fn health() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "service": "FIDO Server",
        "version": env!("CARGO_PKG_VERSION")
    })))
}