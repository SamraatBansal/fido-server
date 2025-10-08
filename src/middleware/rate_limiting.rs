//! Rate limiting middleware

use actix_governor::{Governor, GovernorConfig, PeerIpKeyExtractor};
use std::time::Duration;

/// Configure rate limiter
pub fn rate_limiter() -> GovernorConfig<PeerIpKeyExtractor> {
    GovernorConfig::default()
        .per_second(10)
        .burst_size(20)
        .finish()
}

/// Configure strict rate limiter for sensitive endpoints
pub fn strict_rate_limiter() -> GovernorConfig<PeerIpKeyExtractor> {
    GovernorConfig::default()
        .per_second(5)
        .burst_size(10)
        .finish()
}