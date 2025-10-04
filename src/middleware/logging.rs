//! Logging middleware

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::middleware::Logger;
use std::time::Instant;

/// Custom request logging middleware
pub fn request_logger() -> Logger {
    Logger::new(
        "%a %{r}a \"%r\" %s %b \"%{User-Agent}i\" \"%{Referer}i\" %Dms"
    )
    .exclude("/health")
    .exclude("/health/simple")
    .exclude("/ready")
    .exclude("/live")
}

/// Detailed request logging middleware
pub struct DetailedLogger;

impl DetailedLogger {
    pub fn new() -> Self {
        Self {}
    }
}

impl actix_web::dev::Transform for DetailedLogger {
    type Request = ServiceRequest;
    type Response = ServiceResponse;
    type Error = Error;
    type Transform = DetailedLoggerMiddleware;
    type InitError = ();

    fn new_transform(&self, _service: &impl actix_web::dev::Service<Request = Self::Request, Response = Self::Response, Error = Self::Error, InitError = Self::InitError>) -> Result<Self::Transform, Self::InitError> {
        Ok(DetailedLoggerMiddleware {})
    }
}

pub struct DetailedLoggerMiddleware;

impl<S, B> actix_web::dev::Service for DetailedLoggerMiddleware
where
    S: actix_web::dev::Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = actix_web::dev::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let start_time = Instant::now();
        let method = req.method().clone();
        let path = req.path().to_string();
        let query = req.query_string().to_string();
        let user_agent = req.headers()
            .get("user-agent")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let ip_address = req.connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();
        
        // Get request ID if available
        let request_id = req.extensions()
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let fut = async move {
            // This is a placeholder - in a real implementation, you would
            // wrap the actual service here
            Err(actix_web::error::ErrorInternalServerError("Detailed logger middleware not fully implemented"))
        };
        
        Box::pin(fut)
    }
}

/// Audit logging middleware
pub struct AuditLogger {
    // In a real implementation, you would inject your audit service here
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {}
    }
}

impl actix_web::dev::Transform for AuditLogger {
    type Request = ServiceRequest;
    type Response = ServiceResponse;
    type Error = Error;
    type Transform = AuditLoggerMiddleware;
    type InitError = ();

    fn new_transform(&self, _service: &impl actix_web::dev::Service<Request = Self::Request, Response = Self::Response, Error = Self::Error, InitError = Self::InitError>) -> Result<Self::Transform, Self::InitError> {
        Ok(AuditLoggerMiddleware {})
    }
}

pub struct AuditLoggerMiddleware;

impl<S, B> actix_web::dev::Service for AuditLoggerMiddleware
where
    S: actix_web::dev::Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = actix_web::dev::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let method = req.method().clone();
        let path = req.path().to_string();
        
        // Log sensitive operations
        let should_audit = matches!(method.as_str(), "POST" | "PUT" | "DELETE") ||
            path.contains("/auth/") || 
            path.contains("/register/");
        
        if should_audit {
            log::info!(
                "AUDIT: {} {} from {}",
                method,
                path,
                req.connection_info().realip_remote_addr().unwrap_or("unknown")
            );
        }
        
        let fut = async move {
            // This is a placeholder - in a real implementation, you would
            // wrap the actual service here
            Err(actix_web::error::ErrorInternalServerError("Audit logger middleware not fully implemented"))
        };
        
        Box::pin(fut)
    }
}