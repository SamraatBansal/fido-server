//! Rate limiting middleware (simplified)

/// Configure rate limiter
pub fn rate_limiter() -> String {
    "rate_limiter".to_string()
}

/// Configure strict rate limiter for sensitive endpoints
pub fn strict_rate_limiter() -> String {
    "strict_rate_limiter".to_string()
}