use actix_web::{web, HttpResponse, Result};
use crate::api::handlers;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/attestation")
            .route("/options", web::post().to(handlers::attestation_options))
            .route("/result", web::post().to(handlers::attestation_result))
    )
    .service(
        web::scope("/assertion")
            .route("/options", web::post().to(handlers::assertion_options))
            .route("/result", web::post().to(handlers::assertion_result))
    )
    .route("/health", web::get().to(health_check));
}

async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "fido2-server",
        "version": env!("CARGO_PKG_VERSION")
    })))
}