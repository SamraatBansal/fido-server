//! Logging middleware

use actix_web::middleware::Logger;

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

/// Detailed request logging middleware (placeholder)
pub struct DetailedLogger;

impl DetailedLogger {
    pub fn new() -> Self {
        Self {}
    }
}

/// Audit logging middleware (placeholder)
pub struct AuditLogger;

impl AuditLogger {
    pub fn new() -> Self {
        Self {}
    }
}