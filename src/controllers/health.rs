//! Health check controller

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::db::PgPool;

/// Health check response
#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub version: String,
    pub database: Option<DatabaseStatus>,
}

/// Database status
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseStatus {
    pub status: String,
    pub connection_pool_size: u32,
    pub idle_connections: u32,
}

/// Health controller
pub struct HealthController {
    db_pool: Option<Arc<PgPool>>,
}

impl HealthController {
    /// Create a new health controller
    pub fn new(db_pool: Option<Arc<PgPool>>) -> Self {
        Self { db_pool }
    }

    /// Health check endpoint
    pub async fn health_check(&self, _req: HttpRequest) -> Result<HttpResponse> {
        let mut response = HealthResponse {
            status: "healthy".to_string(),
            timestamp: chrono::Utc::now(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            database: None,
        };

        // Check database connectivity if available
        if let Some(pool) = &self.db_pool {
            match pool.get() {
                Ok(conn) => {
                    use diesel::prelude::*;
                    // Simple query to test connection
                    match diesel::sql_query("SELECT 1").execute(&*conn) {
                        Ok(_) => {
                            let state = pool.state();
                            response.database = Some(DatabaseStatus {
                                status: "healthy".to_string(),
                                connection_pool_size: state.size,
                                idle_connections: state.idle_connections,
                            });
                        }
                        Err(e) => {
                            log::error!("Database health check failed: {}", e);
                            response.status = "unhealthy".to_string();
                            response.database = Some(DatabaseStatus {
                                status: "unhealthy".to_string(),
                                connection_pool_size: 0,
                                idle_connections: 0,
                            });
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to get database connection: {}", e);
                    response.status = "unhealthy".to_string();
                    response.database = Some(DatabaseStatus {
                        status: "unhealthy".to_string(),
                        connection_pool_size: 0,
                        idle_connections: 0,
                    });
                }
            }
        }

        let status_code = if response.status == "healthy" {
            actix_web::http::StatusCode::OK
        } else {
            actix_web::http::StatusCode::SERVICE_UNAVAILABLE
        };

        Ok(HttpResponse::build(status_code).json(response))
    }
}

/// Configure health routes
pub fn configure(cfg: &mut web::ServiceConfig, controller: Arc<HealthController>) {
    cfg.service(
        web::scope("/health")
            .route("", web::get().to({
                let controller = controller.clone();
                move |req| controller.health_check(req)
            }))
    );
}