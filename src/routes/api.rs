//! API routes configuration

use actix_web::web;

pub fn configure_api(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check));
}

async fn health_check() -> actix_web::Result<impl actix_web::Responder> {
    Ok(actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}