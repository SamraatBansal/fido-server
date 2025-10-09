# FIDO2/WebAuthn Security Threat Model and Mitigation Strategies

## Threat Landscape Overview

### 1. Attack Vectors and Threat Actors

#### External Attackers
- **Phishing Attacks**: Malicious websites attempting to steal credentials
- **Man-in-the-Middle**: Network-level interception attempts
- **Replay Attacks**: Reusing captured authentication data
- **Credential Stuffing**: Automated attacks using stolen credentials
- **Social Engineering**: Targeting users to bypass technical controls

#### Internal Threats
- **Malicious Insiders**: Employees with system access
- **Compromised Accounts**: Legitimate accounts under attacker control
- **Supply Chain**: Compromised dependencies or infrastructure

#### Technical Vulnerabilities
- **Implementation Flaws**: Bugs in WebAuthn implementation
- **Cryptographic Weaknesses**: Poor random number generation, weak algorithms
- **Protocol Violations**: Non-compliance with FIDO2 specifications
- **Side-Channel Attacks**: Timing attacks, power analysis

## Detailed Threat Analysis

### 1. Registration Flow Threats

#### T1.1: Malicious Attestation
**Threat**: Attacker provides forged attestation statements
**Impact**: Compromised authenticator trust, potential for future attacks
**Likelihood**: Medium
**Mitigation**:
```rust
// Strict attestation verification
fn verify_attestation(attestation: &AttestationObject) -> Result<(), WebAuthnError> {
    // 1. Verify attestation statement format
    // 2. Validate certificate chain
    // 3. Check against metadata service
    // 4. Verify signature
    // 5. Validate authenticator data
}
```

#### T1.2: Challenge Prediction
**Threat**: Weak random number generation allows challenge prediction
**Impact**: Complete bypass of authentication security
**Likelihood**: Low (if using proper RNG)
**Mitigation**:
```rust
use rand::rngs::OsRng;
use rand::RngCore;

fn generate_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    challenge
}
```

#### T1.3: Origin Spoofing
**Threat**: Attacker registers credentials for spoofed origin
**Impact**: Phishing attacks, credential theft
**Likelihood**: High (without proper validation)
**Mitigation**:
```rust
fn validate_registration_origin(
    client_data: &CollectedClientData,
    allowed_origins: &[String]
) -> Result<(), WebAuthnError> {
    let origin = &client_data.origin;
    if !allowed_origins.contains(origin) {
        return Err(WebAuthnError::InvalidOrigin(origin.clone()));
    }
    Ok(())
}
```

### 2. Authentication Flow Threats

#### T2.1: Signature Replay
**Threat**: Reuse of captured authentication signatures
**Impact**: Unauthorized access using replayed data
**Likelihood**: High (without proper challenge management)
**Mitigation**:
```rust
struct ChallengeManager {
    active_challenges: HashMap<String, Challenge>,
    used_challenges: HashSet<String>,
}

impl ChallengeManager {
    fn validate_and_consume(&mut self, challenge: &str) -> Result<(), WebAuthnError> {
        if self.used_challenges.contains(challenge) {
            return Err(WebAuthnError::ChallengeAlreadyUsed);
        }
        
        let challenge_data = self.active_challenges.remove(challenge)
            .ok_or(WebAuthnError::InvalidChallenge)?;
            
        if challenge_data.is_expired() {
            return Err(WebAuthnError::ChallengeExpired);
        }
        
        self.used_challenges.insert(challenge.to_string());
        Ok(())
    }
}
```

#### T2.2: Counter Regression Attack
**Threat**: Cloned authenticator with reset counter
**Impact**: Undetected use of cloned devices
**Likelihood**: Medium
**Mitigation**:
```rust
fn validate_counter(stored_counter: u32, received_counter: u32) -> Result<(), WebAuthnError> {
    if received_counter <= stored_counter {
        // Log security event
        log::warn!("Counter regression detected: stored={}, received={}", 
                   stored_counter, received_counter);
        return Err(WebAuthnError::CounterRegression);
    }
    Ok(())
}
```

#### T2.3: Cross-Origin Authentication
**Threat**: Authentication credentials used on wrong domain
**Impact**: Credential theft, unauthorized access
**Likelihood**: Medium
**Mitigation**:
```rust
fn validate_rp_id_hash(auth_data: &AuthenticatorData, expected_rp_id: &str) -> Result<(), WebAuthnError> {
    let expected_hash = sha256(expected_rp_id.as_bytes());
    if auth_data.rp_id_hash != expected_hash {
        return Err(WebAuthnError::InvalidRpId);
    }
    Ok(())
}
```

### 3. Storage and Database Threats

#### T3.1: Credential Database Compromise
**Threat**: Unauthorized access to credential database
**Impact**: Mass credential theft, privacy breach
**Likelihood**: Medium
**Mitigation**:
- Database encryption at rest
- Strong access controls
- Regular security audits
- Principle of least privilege

#### T3.2: SQL Injection
**Threat**: Malicious SQL injection through user inputs
**Impact**: Database compromise, data theft
**Likelihood**: Low (with parameterized queries)
**Mitigation**:
```rust
// Use sqlx with compile-time checked queries
async fn get_credential(pool: &PgPool, credential_id: &[u8]) -> Result<Credential, sqlx::Error> {
    sqlx::query_as!(
        Credential,
        "SELECT * FROM credentials WHERE credential_id = $1",
        credential_id
    )
    .fetch_one(pool)
    .await
}
```

#### T3.3: Timing Attacks
**Threat**: Information leakage through response timing
**Impact**: User enumeration, credential existence disclosure
**Likelihood**: Medium
**Mitigation**:
```rust
use subtle::ConstantTimeEq;

fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// Constant-time user lookup
async fn authenticate_user_constant_time(
    username: &str, 
    pool: &PgPool
) -> Result<Option<User>, WebAuthnError> {
    // Always perform database lookup regardless of username validity
    let result = lookup_user(username, pool).await;
    
    // Add constant delay to normalize response times
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    result
}
```

### 4. Transport and Network Threats

#### T4.1: Man-in-the-Middle Attacks
**Threat**: Interception of WebAuthn communications
**Impact**: Credential theft, session hijacking
**Likelihood**: Low (with proper TLS)
**Mitigation**:
- Enforce TLS 1.3
- Certificate pinning
- HSTS headers
- Secure cookie attributes

#### T4.2: DNS Spoofing
**Threat**: Redirection to malicious servers
**Impact**: Complete authentication bypass
**Likelihood**: Medium
**Mitigation**:
- DNS over HTTPS (DoH)
- Certificate transparency monitoring
- DNSSEC validation

### 5. Client-Side Threats

#### T5.1: Malicious Browser Extensions
**Threat**: Extensions intercepting WebAuthn calls
**Impact**: Credential theft, authentication bypass
**Likelihood**: Medium
**Mitigation**:
- Content Security Policy (CSP)
- Subresource Integrity (SRI)
- Regular security awareness training

#### T5.2: Cross-Site Scripting (XSS)
**Threat**: Malicious scripts accessing WebAuthn APIs
**Impact**: Authentication bypass, credential theft
**Likelihood**: Medium
**Mitigation**:
```rust
// Strict CSP headers
fn set_security_headers(response: &mut Response) {
    response.headers_mut().insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none';"
            .parse().unwrap()
    );
    response.headers_mut().insert(
        "X-Frame-Options",
        "DENY".parse().unwrap()
    );
    response.headers_mut().insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap()
    );
}
```

## Security Controls Implementation

### 1. Input Validation
```rust
fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.len() < 3 || username.len() > 64 {
        return Err(ValidationError::InvalidLength);
    }
    
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ValidationError::InvalidCharacters);
    }
    
    Ok(())
}

fn validate_challenge_response(response: &str) -> Result<(), ValidationError> {
    // Validate base64url encoding
    base64::decode_config(response, base64::URL_SAFE_NO_PAD)
        .map_err(|_| ValidationError::InvalidEncoding)?;
    
    Ok(())
}
```

### 2. Rate Limiting
```rust
use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

struct RateLimitingMiddleware {
    limiter: RateLimiter<String, DashMap<String, InMemoryState>, DefaultClock>,
}

impl RateLimitingMiddleware {
    fn new() -> Self {
        let quota = Quota::per_minute(NonZeroU32::new(10).unwrap());
        Self {
            limiter: RateLimiter::dashmap(quota),
        }
    }
    
    fn check_rate_limit(&self, client_ip: &str) -> Result<(), RateLimitError> {
        self.limiter.check_key(&client_ip.to_string())
            .map_err(|_| RateLimitError::TooManyRequests)
    }
}
```

### 3. Audit Logging
```rust
#[derive(Serialize)]
struct SecurityEvent {
    timestamp: DateTime<Utc>,
    event_type: SecurityEventType,
    user_id: Option<String>,
    client_ip: String,
    user_agent: Option<String>,
    details: serde_json::Value,
}

#[derive(Serialize)]
enum SecurityEventType {
    RegistrationAttempt,
    AuthenticationAttempt,
    RegistrationSuccess,
    AuthenticationSuccess,
    RegistrationFailure,
    AuthenticationFailure,
    CounterRegression,
    InvalidOrigin,
    ChallengeReplay,
}

fn log_security_event(event: SecurityEvent) {
    log::info!("SECURITY_EVENT: {}", serde_json::to_string(&event).unwrap());
}
```

## Monitoring and Detection

### 1. Security Metrics
- Authentication success/failure rates
- Registration attempt patterns
- Counter regression incidents
- Challenge timeout rates
- Origin validation failures
- Rate limiting triggers

### 2. Alerting Thresholds
```rust
struct SecurityThresholds {
    max_failed_auth_per_minute: u32,
    max_counter_regressions_per_hour: u32,
    max_origin_validation_failures: u32,
    max_challenge_timeouts_per_hour: u32,
}

impl Default for SecurityThresholds {
    fn default() -> Self {
        Self {
            max_failed_auth_per_minute: 10,
            max_counter_regressions_per_hour: 5,
            max_origin_validation_failures: 20,
            max_challenge_timeouts_per_hour: 100,
        }
    }
}
```

### 3. Incident Response
1. **Automated Response**: Rate limiting, IP blocking, account lockout
2. **Alert Escalation**: Security team notification for critical events
3. **Forensic Logging**: Detailed event capture for investigation
4. **Recovery Procedures**: Account recovery, credential revocation

This threat model provides a comprehensive security framework for the FIDO2/WebAuthn implementation, ensuring robust protection against known attack vectors while maintaining usability and compliance with security standards.