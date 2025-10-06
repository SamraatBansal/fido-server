//! API route configuration

use actix_web::{web, Scope};
use crate::config::Config;
use crate::controllers::{FidoController, UserController};
use crate::middleware::{cors, rate_limit, security};
use crate::services::FidoService;

/// Configure API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Load configuration
    let config = crate::config::load_config().unwrap_or_else(|_| Config::default());
    
    // Initialize services
    let fido_service = FidoService::new(config.webauthn.clone()).expect("Failed to create FIDO service");
    let fido_controller = web::Data::new(FidoController::new(fido_service));
    let user_controller = web::Data::new(UserController::new());

    // Configure CORS
    let cors = cors::configure_cors(&config.server);
    
    // Configure rate limiting
    let rate_limit = rate_limit::RateLimitMiddleware::new(config.security.rate_limit_per_minute);
    
    // Configure security headers
    let security_headers = security::SecurityHeadersMiddleware::new();

    cfg.service(
        web::scope("")
            .wrap(cors)
            .wrap(rate_limit)
            .wrap(security_headers)
            .configure(|cfg| crate::controllers::fido::configure(cfg, fido_controller.clone()))
            .configure(|cfg| crate::controllers::user::configure(cfg, user_controller.clone()))
    );
}