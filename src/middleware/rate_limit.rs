//! Rate limiting middleware

use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_lab::middleware::Next;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Simple in-memory rate limiter
/// In production, you'd want to use Redis or another distributed store
#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: Duration::from_secs(window_secs),
        }
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        
        // Check if under limit
        if entry.len() < self.max_requests as usize {
            entry.push(now);
            true
        } else {
            false
        }
    }
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    req: ServiceRequest,
    next: Next<impl actix_web::MessageBody>,
) -> Result<actix_web::HttpResponse, Error> {
    // Get client IP
    let client_ip = req
        .connection_info()
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Create rate limiter (in production, this would be shared state)
    let rate_limiter = RateLimiter::new(60, 60); // 60 requests per minute
    
    if !rate_limiter.is_allowed(&client_ip) {
        return Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded"));
    }

    let res = next.call(req).await?;
    Ok(res)
}

/// Rate limiting middleware with custom configuration
pub fn create_rate_limit_middleware(max_requests: u32, window_secs: u64) -> Arc<dyn Fn(ServiceRequest, Next<impl actix_web::MessageBody>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<actix_web::HttpResponse, Error>>>> + Send + Sync> {
    let rate_limiter = Arc::new(RateLimiter::new(max_requests, window_secs));
    
    Arc::new(move |req: ServiceRequest, next: Next<impl actix_web::MessageBody>| {
        let rate_limiter = rate_limiter.clone();
        
        Box::pin(async move {
            // Get client IP
            let client_ip = req
                .connection_info()
                .peer_addr()
                .map(|addr| addr.ip().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            if !rate_limiter.is_allowed(&client_ip) {
                return Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded"));
            }

            let res = next.call(req).await?;
            Ok(res)
        })
    })
}