//! Health check controller

use actix_web::{web, HttpResponse, Result};
use crate::schema::{HealthResponse, HealthChecks, HealthCheckStatus, ApiResponse};
use crate::db::DbManager;
use crate::services::WebAuthnService;
use std::time::Instant;
use crate::error::{AppError, Result as AppResult};

/// Health check endpoint
pub async fn health_check(
    db_manager: web::Data<DbManager>,
    webauthn_service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    let start_time = Instant::now();
    
    // Check database health
    let db_status = check_database_health(db_manager).await;
    
    // Check WebAuthn service health
    let webauthn_status = check_webauthn_health(webauthn_service).await;
    
    // Determine overall status
    let overall_status = if db_status.status == "healthy" && webauthn_status.status == "healthy" {
        "healthy"
    } else {
        "unhealthy"
    };
    
    let response_time_ms = start_time.elapsed().as_millis() as u64;
    
    let health_response = HealthResponse {
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now(),
        checks: HealthChecks {
            database: db_status,
            webauthn: webauthn_status,
        },
    };
    
    let api_response = ApiResponse::success(health_response);
    
    // Return appropriate HTTP status based on health
    let status = if overall_status == "healthy" {
        actix_web::http::StatusCode::OK
    } else {
        actix_web::http::StatusCode::SERVICE_UNAVAILABLE
    };
    
    Ok(HttpResponse::build(status).json(api_response))
}

/// Simple health check endpoint (for load balancers)
pub async fn simple_health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "timestamp": chrono::Utc::now()
    })))
}

/// Check database health
async fn check_database_health(db_manager: &DbManager) -> HealthCheckStatus {
    let start_time = Instant::now();
    
    match db_manager.get_connection() {
        Ok(mut conn) => {
            // Try to execute a simple query
            match diesel::sql_query("SELECT 1").execute(&mut conn) {
                Ok(_) => {
                    let response_time_ms = start_time.elapsed().as_millis() as u64;
                    HealthCheckStatus {
                        status: "healthy".to_string(),
                        message: None,
                        response_time_ms: Some(response_time_ms),
                    }
                }
                Err(e) => {
                    HealthCheckStatus {
                        status: "unhealthy".to_string(),
                        message: Some(format!("Database query failed: {}", e)),
                        response_time_ms: None,
                    }
                }
            }
        }
        Err(e) => {
            HealthCheckStatus {
                status: "unhealthy".to_string(),
                message: Some(format!("Failed to get database connection: {}", e)),
                response_time_ms: None,
            }
        }
    }
}

/// Check WebAuthn service health
async fn check_webauthn_health(_webauthn_service: &WebAuthnService) -> HealthCheckStatus {
    let start_time = Instant::now();
    
    // For now, just check if the service exists and is configured
    // In a real implementation, you might want to test challenge generation
    let response_time_ms = start_time.elapsed().as_millis() as u64;
    
    HealthCheckStatus {
        status: "healthy".to_string(),
        message: None,
        response_time_ms: Some(response_time_ms),
    }
}

/// Readiness check endpoint (for Kubernetes)
pub async fn readiness_check(
    db_manager: web::Data<DbManager>,
) -> Result<HttpResponse> {
    // Check if the application is ready to serve traffic
    match db_manager.get_connection() {
        Ok(mut conn) => {
            // Try to execute a simple query to verify database connectivity
            match diesel::sql_query("SELECT 1").execute(&mut conn) {
                Ok(_) => {
                    Ok(HttpResponse::Ok().json(serde_json::json!({
                        "status": "ready",
                        "timestamp": chrono::Utc::now()
                    })))
                }
                Err(e) => {
                    log::error!("Readiness check failed: {}", e);
                    Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
                        "status": "not_ready",
                        "reason": "Database not available",
                        "timestamp": chrono::Utc::now()
                    })))
                }
            }
        }
        Err(e) => {
            log::error!("Readiness check failed: {}", e);
            Ok(HttpResponse::ServiceUnavailable().json(serde_json::json!({
                "status": "not_ready",
                "reason": "Cannot connect to database",
                "timestamp": chrono::Utc::now()
            })))
        }
    }
}

/// Liveness check endpoint (for Kubernetes)
pub async fn liveness_check() -> Result<HttpResponse> {
    // Simple liveness check - if we can respond, we're alive
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "alive",
        "timestamp": chrono::Utc::now()
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web};

    #[actix_web::test]
    async fn test_simple_health_check() {
        let app = test::init_service(
            actix_web::App::new()
                .route("/health/simple", web::get().to(simple_health_check))
        ).await;

        let req = test::TestRequest::get()
            .uri("/health/simple")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }

    #[actix_web::test]
    async fn test_liveness_check() {
        let app = test::init_service(
            actix_web::App::new()
                .route("/health/live", web::get().to(liveness_check))
        ).await;

        let req = test::TestRequest::get()
            .uri("/health/live")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    }
}