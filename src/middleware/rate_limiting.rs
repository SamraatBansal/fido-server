//! Rate limiting middleware

use actix_governor::{GovernorConfig, PeerIpKeyExtractor, governor::middleware::NoOpMiddleware};
use std::num::NonZeroU32;

/// Configure rate limiter
pub fn rate_limiter() -> GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware> {
    GovernorConfig::builder()
        .per_second(NonZeroU32::new(10).unwrap())
        .burst_size(NonZeroU32::new(20).unwrap())
        .finish()
}

/// Configure strict rate limiter for sensitive endpoints
pub fn strict_rate_limiter() -> GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware> {
    GovernorConfig::builder()
        .per_second(NonZeroU32::new(5).unwrap())
        .burst_size(NonZeroU32::new(10).unwrap())
        .finish()
}