# Security Controls Implementation Guide

## Overview

This document provides detailed implementation guidance for security controls in the FIDO2/WebAuthn Relying Party Server, focusing on specific code implementations and testing strategies.

## 1. Origin Validation Implementation

### 1.1 Origin Validation Service

```rust
use url::Url;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct OriginValidator {
    allowed_origins: HashSet<String>,
    allowed_rp_ids: HashSet<String>,
}

impl OriginValidator {
    pub fn new(allowed_origins: Vec<String>) -> Result<Self, ValidationError> {
        let mut allowed_rp_ids = HashSet::new();
        let origins_set: HashSet<String> = allowed_origins.into_iter().collect();
        
        // Extract RP IDs from origins
        for origin in &origins_set {
            let url = Url::parse(origin)
                .map_err(|_| ValidationError::InvalidOrigin(origin.clone()))?;
            
            if let Some(host) = url.host_str() {
                allowed_rp_ids.insert(host.to_string());
            }
        }
        
        Ok(Self {
            allowed_origins: origins_set,
            allowed_rp_ids,
        })
    }
    
    pub fn validate_origin(&self, origin: &str) -> Result<(), ValidationError> {
        if !self.allowed_origins.contains(origin) {
            return Err(ValidationError::UnauthorizedOrigin(origin.to_string()));
        }
        
        // Additional validation: ensure HTTPS
        if !origin.starts_with("https://") {
            return Err(ValidationError::InsecureOrigin(origin.to_string()));
        }
        
        Ok(())
    }
    
    pub fn validate_rp_id(&self, rp_id: &str, origin: &str) -> Result<(), ValidationError> {
        // Validate RP ID is in allowed list
        if !self.allowed_rp_ids.contains(rp_id) {
            return Err(ValidationError::UnauthorizedRpId(rp_id.to_string()));
        }
        
        // Validate RP ID matches origin
        let url = Url::parse(origin)
            .map_err(|_| ValidationError::InvalidOrigin(origin.to_string()))?;
        
        if let Some(host) = url.host_str() {
            if host != rp_id && !host.ends_with(&format!(".{}", rp_id)) {
                return Err(ValidationError::RpIdOriginMismatch {
                    rp_id: rp_id.to_string(),
                    origin: origin.to_string(),
                });
            }
        }
        
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Invalid origin format: {0}")]
    InvalidOrigin(String),
    #[error("Unauthorized origin: {0}")]
    UnauthorizedOrigin(String),
    #[error("Insecure origin (HTTPS required): {0}")]
    InsecureOrigin(String),
    #[error("Unauthorized RP ID: {0}")]
    UnauthorizedRpId(String),
    #[error("RP ID {rp_id} does not match origin {origin}")]
    RpIdOriginMismatch { rp_id: String, origin: String },
}
```

### 1.2 Origin Validation Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_valid_origin_validation() {
        let validator = OriginValidator::new(vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ]).unwrap();
        
        assert!(validator.validate_origin("https://example.com").is_ok());
        assert!(validator.validate_origin("https://app.example.com").is_ok());
    }
    
    #[test]
    fn test_invalid_origin_rejection() {
        let validator = OriginValidator::new(vec![
            "https://example.com".to_string(),
        ]).unwrap();
        
        // Test unauthorized origin
        assert!(validator.validate_origin("https://evil.com").is_err());
        
        // Test insecure origin
        assert!(validator.validate_origin("http://example.com").is_err());
        
        // Test subdomain attack
        assert!(validator.validate_origin("https://fakeexample.com").is_err());
    }
    
    #[test]
    fn test_rp_id_validation() {
        let validator = OriginValidator::new(vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ]).unwrap();
        
        // Valid RP ID matching origin
        assert!(validator.validate_rp_id("example.com", "https://example.com").is_ok());
        assert!(validator.validate_rp_id("example.com", "https://app.example.com").is_ok());
        
        // Invalid RP ID
        assert!(validator.validate_rp_id("evil.com", "https://example.com").is_err());
    }
}
```

## 2. Challenge Management with Replay Prevention

### 2.1 Challenge Service Implementation

```rust
use rand::{RngCore, thread_rng};
use base64::URL_SAFE_NO_PAD;
use time::{Duration, OffsetDateTime};
use std::collections::HashMap;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge: Vec<u8>,
    pub challenge_type: ChallengeType,
    pub expires_at: OffsetDateTime,
    pub used: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeType {
    Attestation,
    Assertion,
}

pub struct ChallengeService {
    storage: Arc<dyn ChallengeStorage>,
    challenge_ttl: Duration,
}

impl ChallengeService {
    pub fn new(storage: Arc<dyn ChallengeStorage>) -> Self {
        Self {
            storage,
            challenge_ttl: Duration::minutes(5), // FIDO2 recommended TTL
        }
    }
    
    pub async fn generate_challenge(
        &self,
        user_id: Uuid,
        challenge_type: ChallengeType,
    ) -> Result<Vec<u8>, ChallengeError> {
        // Generate cryptographically secure random challenge (32+ bytes)
        let mut challenge_bytes = vec![0u8; 32];
        thread_rng().fill_bytes(&mut challenge_bytes);
        
        let challenge = Challenge {
            id: Uuid::new_v4(),
            user_id,
            challenge: challenge_bytes.clone(),
            challenge_type,
            expires_at: OffsetDateTime::now_utc() + self.challenge_ttl,
            used: false,
        };
        
        // Store challenge for later verification
        self.storage.store_challenge(&challenge).await?;
        
        // Start cleanup task for expired challenges
        self.cleanup_expired_challenges().await?;
        
        Ok(challenge_bytes)
    }
    
    pub async fn verify_and_consume_challenge(
        &self,
        user_id: Uuid,
        challenge_bytes: &[u8],
        challenge_type: ChallengeType,
    ) -> Result<(), ChallengeError> {
        let challenge = self.storage
            .get_challenge(user_id, challenge_type.clone())
            .await?
            .ok_or(ChallengeError::ChallengeNotFound)?;
        
        // Verify challenge matches
        if challenge.challenge != challenge_bytes {
            return Err(ChallengeError::ChallengeMismatch);
        }
        
        // Verify challenge type matches
        if challenge.challenge_type != challenge_type {
            return Err(ChallengeError::InvalidChallengeType);
        }
        
        // Verify challenge is not expired
        if OffsetDateTime::now_utc() > challenge.expires_at {
            return Err(ChallengeError::ChallengeExpired);
        }
        
        // Verify challenge is not already used (replay prevention)
        if challenge.used {
            return Err(ChallengeError::ChallengeAlreadyUsed);
        }
        
        // Mark challenge as used to prevent replay
        self.storage.mark_challenge_used(challenge.id).await?;
        
        Ok(())
    }
    
    async fn cleanup_expired_challenges(&self) -> Result<(), ChallengeError> {
        let cleaned = self.storage.cleanup_expired_challenges().await?;
        tracing::debug!("Cleaned up {} expired challenges", cleaned);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChallengeError {
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("Challenge mismatch")]
    ChallengeMismatch,
    #[error("Invalid challenge type")]
    InvalidChallengeType,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge already used")]
    ChallengeAlreadyUsed,
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}
```

### 2.2 Challenge Storage Interface

```rust
#[async_trait]
pub trait ChallengeStorage: Send + Sync {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<(), StorageError>;
    async fn get_challenge(
        &self,
        user_id: Uuid,
        challenge_type: ChallengeType,
    ) -> Result<Option<Challenge>, StorageError>;
    async fn mark_challenge_used(&self, challenge_id: Uuid) -> Result<(), StorageError>;
    async fn cleanup_expired_challenges(&self) -> Result<u64, StorageError>;
}

// In-memory implementation for testing
pub struct InMemoryChallengeStorage {
    challenges: RwLock<HashMap<Uuid, Challenge>>,
}

impl InMemoryChallengeStorage {
    pub fn new() -> Self {
        Self {
            challenges: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ChallengeStorage for InMemoryChallengeStorage {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<(), StorageError> {
        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.id, challenge.clone());
        Ok(())
    }
    
    async fn get_challenge(
        &self,
        user_id: Uuid,
        challenge_type: ChallengeType,
    ) -> Result<Option<Challenge>, StorageError> {
        let challenges = self.challenges.read().await;
        let challenge = challenges
            .values()
            .find(|c| c.user_id == user_id && c.challenge_type == challenge_type && !c.used)
            .cloned();
        Ok(challenge)
    }
    
    async fn mark_challenge_used(&self, challenge_id: Uuid) -> Result<(), StorageError> {
        let mut challenges = self.challenges.write().await;
        if let Some(challenge) = challenges.get_mut(&challenge_id) {
            challenge.used = true;
        }
        Ok(())
    }
    
    async fn cleanup_expired_challenges(&self) -> Result<u64, StorageError> {
        let mut challenges = self.challenges.write().await;
        let now = OffsetDateTime::now_utc();
        let initial_count = challenges.len();
        
        challenges.retain(|_, challenge| challenge.expires_at > now);
        
        Ok((initial_count - challenges.len()) as u64)
    }
}
```

## 3. Rate Limiting and DDoS Protection

### 3.1 Rate Limiting Middleware

```rust
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use time::{Duration, OffsetDateTime};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst_limit: u32,
    pub window_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_limit: 10,
            window_duration: Duration::minutes(1),
        }
    }
}

#[derive(Debug)]
struct RateLimitEntry {
    count: u32,
    window_start: OffsetDateTime,
}

pub struct RateLimiter {
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    config: RateLimitConfig,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
    
    pub async fn check_rate_limit(&self, client_id: &str) -> Result<(), RateLimitError> {
        let mut entries = self.entries.write().await;
        let now = OffsetDateTime::now_utc();
        
        let entry = entries.entry(client_id.to_string()).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });
        
        // Reset window if expired
        if now - entry.window_start > self.config.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }
        
        // Check burst limit
        if entry.count >= self.config.burst_limit {
            return Err(RateLimitError::BurstLimitExceeded);
        }
        
        // Check rate limit
        if entry.count >= self.config.requests_per_minute {
            return Err(RateLimitError::RateLimitExceeded);
        }
        
        entry.count += 1;
        Ok(())
    }
    
    pub async fn cleanup_expired_entries(&self) {
        let mut entries = self.entries.write().await;
        let now = OffsetDateTime::now_utc();
        
        entries.retain(|_, entry| {
            now - entry.window_start <= self.config.window_duration
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Burst limit exceeded")]
    BurstLimitExceeded,
}

// Axum middleware implementation
pub fn rate_limit_middleware(
    rate_limiter: Arc<RateLimiter>,
) -> impl Fn(Request<Body>, Next<Body>) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> + Clone {
    move |req: Request<Body>, next: Next<Body>| {
        let rate_limiter = rate_limiter.clone();
        Box::pin(async move {
            // Extract client identifier (IP address)
            let client_ip = req
                .headers()
                .get("x-forwarded-for")
                .and_then(|hv| hv.to_str().ok())
                .or_else(|| {
                    req.extensions()
                        .get::<ConnectInfo<SocketAddr>>()
                        .map(|ci| ci.0.ip().to_string().as_str())
                })
                .unwrap_or("unknown");
            
            // Check rate limit
            match rate_limiter.check_rate_limit(client_ip).await {
                Ok(()) => next.run(req).await,
                Err(RateLimitError::RateLimitExceeded) => {
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("Retry-After", "60")
                        .body(Body::from("Rate limit exceeded"))
                        .unwrap()
                }
                Err(RateLimitError::BurstLimitExceeded) => {
                    Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("Retry-After", "60")
                        .body(Body::from("Burst limit exceeded"))
                        .unwrap()
                }
            }
        })
    }
}
```

## 4. Counter Validation and Anti-Cloning Protection

### 4.1 Counter Validation Service

```rust
pub struct CounterValidator {
    storage: Arc<dyn CredentialStorage>,
}

impl CounterValidator {
    pub fn new(storage: Arc<dyn CredentialStorage>) -> Self {
        Self { storage }
    }
    
    pub async fn validate_and_update_counter(
        &self,
        credential_id: &[u8],
        new_counter: u32,
    ) -> Result<(), CounterError> {
        let credential = self.storage
            .get_credential(credential_id)
            .await?
            .ok_or(CounterError::CredentialNotFound)?;
        
        // Check for counter rollback (potential cloning)
        if new_counter <= credential.counter {
            // Log security event
            tracing::warn!(
                "Counter rollback detected for credential {:?}: {} -> {}",
                credential_id,
                credential.counter,
                new_counter
            );
            
            return Err(CounterError::CounterRollback {
                old_counter: credential.counter,
                new_counter,
            });
        }
        
        // Check for unreasonable counter jump (potential attack)
        let counter_jump = new_counter - credential.counter;
        if counter_jump > 1000 {
            tracing::warn!(
                "Large counter jump detected for credential {:?}: {}",
                credential_id,
                counter_jump
            );
            
            return Err(CounterError::SuspiciousCounterJump(counter_jump));
        }
        
        // Update counter in storage
        self.storage
            .update_credential_counter(credential_id, new_counter)
            .await?;
        
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CounterError {
    #[error("Credential not found")]
    CredentialNotFound,
    #[error("Counter rollback detected: {old_counter} -> {new_counter}")]
    CounterRollback { old_counter: u32, new_counter: u32 },
    #[error("Suspicious counter jump: {0}")]
    SuspiciousCounterJump(u32),
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}
```

## 5. Comprehensive Security Testing

### 5.1 Security Test Suite

```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[tokio::test]
    async fn test_challenge_replay_prevention() {
        let storage = Arc::new(InMemoryChallengeStorage::new());
        let service = ChallengeService::new(storage);
        let user_id = Uuid::new_v4();
        
        // Generate challenge
        let challenge = service
            .generate_challenge(user_id, ChallengeType::Attestation)
            .await
            .unwrap();
        
        // First use should succeed
        assert!(service
            .verify_and_consume_challenge(user_id, &challenge, ChallengeType::Attestation)
            .await
            .is_ok());
        
        // Second use should fail (replay attack)
        assert!(matches!(
            service
                .verify_and_consume_challenge(user_id, &challenge, ChallengeType::Attestation)
                .await,
            Err(ChallengeError::ChallengeAlreadyUsed)
        ));
    }
    
    #[tokio::test]
    async fn test_origin_spoofing_prevention() {
        let validator = OriginValidator::new(vec![
            "https://legitimate.com".to_string(),
        ]).unwrap();
        
        // Test various spoofing attempts
        let spoofing_attempts = vec![
            "https://legitimate.com.evil.com",
            "https://evillegitimate.com",
            "https://legitimate.com.evil.com",
            "http://legitimate.com", // Insecure
        ];
        
        for attempt in spoofing_attempts {
            assert!(
                validator.validate_origin(attempt).is_err(),
                "Should reject spoofing attempt: {}",
                attempt
            );
        }
    }
    
    #[tokio::test]
    async fn test_counter_rollback_detection() {
        let storage = Arc::new(InMemoryCredentialStorage::new());
        let validator = CounterValidator::new(storage.clone());
        
        let credential_id = b"test-credential-id";
        
        // Store initial credential with counter = 10
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            credential_id: credential_id.to_vec(),
            public_key: vec![],
            counter: 10,
            // ... other fields
        };
        storage.store_credential(&credential).await.unwrap();
        
        // Valid counter increment should succeed
        assert!(validator
            .validate_and_update_counter(credential_id, 11)
            .await
            .is_ok());
        
        // Counter rollback should fail
        assert!(matches!(
            validator.validate_and_update_counter(credential_id, 10).await,
            Err(CounterError::CounterRollback { .. })
        ));
    }
    
    #[tokio::test]
    async fn test_rate_limiting() {
        let config = RateLimitConfig {
            requests_per_minute: 5,
            burst_limit: 3,
            window_duration: Duration::minutes(1),
        };
        let limiter = RateLimiter::new(config);
        let client_id = "test-client";
        
        // First 3 requests should succeed (within burst limit)
        for _ in 0..3 {
            assert!(limiter.check_rate_limit(client_id).await.is_ok());
        }
        
        // 4th request should fail (burst limit exceeded)
        assert!(matches!(
            limiter.check_rate_limit(client_id).await,
            Err(RateLimitError::BurstLimitExceeded)
        ));
    }
    
    #[tokio::test]
    async fn test_timing_attack_resistance() {
        let validator = OriginValidator::new(vec![
            "https://valid.com".to_string(),
        ]).unwrap();
        
        // Measure timing for valid and invalid origins
        let valid_times = measure_validation_time(&validator, "https://valid.com", 100).await;
        let invalid_times = measure_validation_time(&validator, "https://invalid.com", 100).await;
        
        // Check that timing difference is not significant (< 10% difference)
        let avg_valid = valid_times.iter().sum::<u64>() / valid_times.len() as u64;
        let avg_invalid = invalid_times.iter().sum::<u64>() / invalid_times.len() as u64;
        
        let diff_ratio = if avg_valid > avg_invalid {
            (avg_valid - avg_invalid) as f64 / avg_valid as f64
        } else {
            (avg_invalid - avg_valid) as f64 / avg_invalid as f64
        };
        
        assert!(diff_ratio < 0.1, "Timing difference too large: {:.2}%", diff_ratio * 100.0);
    }
    
    async fn measure_validation_time(
        validator: &OriginValidator,
        origin: &str,
        iterations: usize,
    ) -> Vec<u64> {
        let mut times = Vec::new();
        
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            let _ = validator.validate_origin(origin);
            let elapsed = start.elapsed().as_nanos() as u64;
            times.push(elapsed);
        }
        
        times
    }
}
```

## 6. Security Monitoring and Alerting

### 6.1 Security Event Logging

```rust
use tracing::{info, warn, error};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub severity: SecuritySeverity,
    pub timestamp: OffsetDateTime,
    pub client_ip: Option<String>,
    pub user_id: Option<Uuid>,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub enum SecurityEventType {
    UnauthorizedOrigin,
    ChallengeReplay,
    CounterRollback,
    RateLimitExceeded,
    SuspiciousActivity,
    AttestationFailure,
    AssertionFailure,
}

#[derive(Debug, Serialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log_security_event(event: SecurityEvent) {
        match event.severity {
            SecuritySeverity::Low => info!("Security event: {:?}", event),
            SecuritySeverity::Medium => warn!("Security event: {:?}", event),
            SecuritySeverity::High | SecuritySeverity::Critical => {
                error!("Security event: {:?}", event);
                // Trigger alerting for high/critical events
                Self::trigger_alert(&event);
            }
        }
    }
    
    fn trigger_alert(event: &SecurityEvent) {
        // Implementation for alerting system integration
        // Could send to monitoring system, email, Slack, etc.
        tracing::error!("SECURITY ALERT: {:?}", event);
    }
}
```

This comprehensive security controls implementation provides:

1. **Robust origin validation** with subdomain attack prevention
2. **Challenge management** with cryptographic security and replay prevention
3. **Rate limiting** to prevent DoS attacks
4. **Counter validation** to detect authenticator cloning
5. **Comprehensive security testing** covering all attack vectors
6. **Security monitoring** with event logging and alerting

Each component includes detailed test cases to validate security properties and ensure proper functioning under attack conditions.