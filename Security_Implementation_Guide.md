# FIDO2/WebAuthn Security Implementation Guide

## 1. Security Architecture Overview

### 1.1 Defense in Depth Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                    External Threat Surface                  │
├─────────────────────────────────────────────────────────────┤
│  Network Security Layer                                     │
│  ├── TLS 1.3 with Perfect Forward Secrecy                  │
│  ├── HSTS and Security Headers                             │
│  ├── DDoS Protection                                       │
│  └── Network Segmentation                                  │
├─────────────────────────────────────────────────────────────┤
│  Application Security Layer                                 │
│  ├── Input Validation & Sanitization                       │
│  ├── Authentication & Authorization                        │
│  ├── Rate Limiting & Throttling                            │
│  ├── CORS & CSP Policies                                   │
│  └── CSRF Protection                                        │
├─────────────────────────────────────────────────────────────┤
│  WebAuthn Protocol Security Layer                           │
│  ├── Challenge-Response Verification                        │
│  ├── Origin & RP ID Validation                             │
│  ├── Attestation Statement Verification                    │
│  ├── Signature Verification                                 │
│  └── Replay Attack Prevention                              │
├─────────────────────────────────────────────────────────────┤
│  Data Security Layer                                        │
│  ├── Encryption at Rest (AES-256-GCM)                      │
│  ├── Encrypted Database Connections                         │
│  ├── Key Management & Rotation                             │
│  ├── Secure Credential Storage                              │
│  └── Audit Logging                                          │
├─────────────────────────────────────────────────────────────┤
│  Infrastructure Security Layer                              │
│  ├── Container Security                                     │
│  ├── Host Security                                          │
│  ├── Access Control                                         │
│  ├── Monitoring & Alerting                                  │
│  └── Backup & Recovery                                      │
└─────────────────────────────────────────────────────────────┘
```

## 2. Critical Security Controls

### 2.1 WebAuthn Protocol Security

#### **Challenge Management**
```rust
use rand::{distributions::Alphanumeric, Rng};
use std::time::{SystemTime, Duration};

pub struct ChallengeManager {
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
    cleanup_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct ChallengeEntry {
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: ChallengeType,
    pub expires_at: SystemTime,
    pub created_at: SystemTime,
    pub client_data_hash: Option<Vec<u8>>,
}

impl ChallengeManager {
    pub fn generate_challenge(&self, length: usize) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
    
    pub fn store_challenge(&self, 
        challenge: String, 
        user_id: Option<Uuid>,
        challenge_type: ChallengeType,
        timeout: Duration
    ) -> Result<()> {
        let entry = ChallengeEntry {
            challenge: challenge.clone(),
            user_id,
            challenge_type,
            expires_at: SystemTime::now() + timeout,
            created_at: SystemTime::now(),
            client_data_hash: None,
        };
        
        let mut challenges = self.challenges.write().unwrap();
        challenges.insert(challenge, entry);
        
        Ok(())
    }
    
    pub fn verify_and_consume_challenge(&self, 
        challenge: &str,
        expected_type: ChallengeType
    ) -> Result<ChallengeEntry> {
        let mut challenges = self.challenges.write().unwrap();
        
        if let Some(entry) = challenges.remove(challenge) {
            if entry.challenge_type != expected_type {
                return Err(SecurityError::InvalidChallengeType.into());
            }
            
            if SystemTime::now() > entry.expires_at {
                return Err(SecurityError::ChallengeExpired.into());
            }
            
            Ok(entry)
        } else {
            Err(SecurityError::ChallengeNotFound.into())
        }
    }
}
```

#### **Origin and RP ID Validation**
```rust
use url::Url;

pub struct OriginValidator {
    allowed_origins: HashSet<String>,
    rp_id: String,
}

impl OriginValidator {
    pub fn new(allowed_origins: Vec<String>, rp_id: String) -> Self {
        Self {
            allowed_origins: allowed_origins.into_iter().collect(),
            rp_id,
        }
    }
    
    pub fn validate_origin(&self, origin: &str) -> Result<()> {
        if !self.allowed_origins.contains(origin) {
            security_event!(
                SecurityLevel::High,
                "Invalid origin attempted",
                origin = origin
            );
            return Err(SecurityError::InvalidOrigin.into());
        }
        Ok(())
    }
    
    pub fn validate_rp_id(&self, rp_id: &str) -> Result<()> {
        if rp_id != self.rp_id {
            security_event!(
                SecurityLevel::High,
                "Invalid RP ID attempted",
                rp_id = rp_id
            );
            return Err(SecurityError::InvalidRpId.into());
        }
        Ok(())
    }
    
    pub fn validate_effective_domain(&self, origin: &str) -> Result<()> {
        let url = Url::parse(origin)
            .map_err(|_| SecurityError::InvalidOrigin)?;
        
        let host = url.host_str()
            .ok_or(SecurityError::InvalidOrigin)?;
        
        // Check if the effective domain matches RP ID
        if !host.ends_with(&self.rp_id) && host != &self.rp_id {
            return Err(SecurityError::InvalidEffectiveDomain.into());
        }
        
        Ok(())
    }
}
```

### 2.2 Cryptographic Security

#### **Secure Random Number Generation**
```rust
use rand::{rngs::OsRng, RngCore};

pub struct SecureRandom;

impl SecureRandom {
    pub fn generate_bytes(length: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }
    
    pub fn generate_challenge_base64(length: usize) -> String {
        let bytes = Self::generate_bytes(length);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    
    pub fn generate_uuid() -> Uuid {
        Uuid::new_v4()
    }
}

// Security audit for random number generation
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_uniqueness() {
        let mut challenges = HashSet::new();
        
        for _ in 0..1000 {
            let challenge = SecureRandom::generate_challenge_base64(32);
            assert!(!challenges.contains(&challenge), "Duplicate challenge generated");
            challenges.insert(challenge);
        }
    }
    
    #[test]
    fn test_random_entropy() {
        let bytes1 = SecureRandom::generate_bytes(32);
        let bytes2 = SecureRandom::generate_bytes(32);
        
        assert_ne!(bytes1, bytes2, "Random bytes should be unique");
        
        // Basic entropy check (not comprehensive)
        let mut sum = 0u64;
        for byte in &bytes1 {
            sum += *byte as u64;
        }
        
        // Should be roughly half of maximum possible sum
        let expected_sum = 32 * 128; // Average of 0-255 is 127.5
        assert!((sum as i64 - expected_sum as i64).abs() < expected_sum as i64 / 2);
    }
}
```

#### **Signature Verification**
```rust
use webauthn_rs::proto::{AuthenticatorData, ClientDataJSON};
use p256::{ecdsa::Signature, PublicKey};

pub struct SignatureVerifier;

impl SignatureVerifier {
    pub fn verify_attestation_signature(
        public_key: &[u8],
        auth_data: &[u8],
        client_data_hash: &[u8],
        signature: &[u8],
        algorithm: i32,
    ) -> Result<()> {
        match algorithm {
            -7 => Self::verify_es256(public_key, auth_data, client_data_hash, signature),
            -257 => Self::verify_rs256(public_key, auth_data, client_data_hash, signature),
            -8 => Self::verify_eddsa(public_key, auth_data, client_data_hash, signature),
            _ => Err(SecurityError::UnsupportedAlgorithm.into()),
        }
    }
    
    fn verify_es256(
        public_key: &[u8],
        auth_data: &[u8],
        client_data_hash: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use p256::ecdsa::{VerifyingKey, Signature};
        use sha2::{Sha256, Digest};
        
        // Parse public key
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| SecurityError::InvalidPublicKey)?;
        
        // Create signature
        let signature = Signature::from_der(signature)
            .map_err(|_| SecurityError::InvalidSignature)?;
        
        // Create message to verify
        let mut hasher = Sha256::new();
        hasher.update(auth_data);
        hasher.update(client_data_hash);
        let message = hasher.finalize();
        
        // Verify signature
        verifying_key.verify(&message, &signature)
            .map_err(|_| SecurityError::SignatureVerificationFailed)?;
        
        Ok(())
    }
    
    fn verify_rs256(
        public_key: &[u8],
        auth_data: &[u8],
        client_data_hash: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        use rsa::{RsaPublicKey, pkcs1v15::VerifyingKey};
        use sha2::{Sha256, Digest};
        
        // Parse public key
        let public_key = RsaPublicKey::from_public_key_der(public_key)
            .map_err(|_| SecurityError::InvalidPublicKey)?;
        
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        
        // Create message to verify
        let mut hasher = Sha256::new();
        hasher.update(auth_data);
        hasher.update(client_data_hash);
        let message = hasher.finalize();
        
        // Verify signature
        verifying_key.verify(&message, signature)
            .map_err(|_| SecurityError::SignatureVerificationFailed)?;
        
        Ok(())
    }
}
```

### 2.3 Data Protection

#### **Encrypted Credential Storage**
```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};

pub struct CredentialEncryption {
    cipher: Aes256Gcm,
}

impl CredentialEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        Self {
            cipher: Aes256Gcm::new(key),
        }
    }
    
    pub fn encrypt_credential_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Nonce::from_slice(&SecureRandom::generate_bytes(12));
        
        let ciphertext = self.cipher.encrypt(nonce, data)
            .map_err(|_| SecurityError::EncryptionFailed)?;
        
        // Return nonce + ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    pub fn decrypt_credential_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(SecurityError::InvalidEncryptedData.into());
        }
        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| SecurityError::DecryptionFailed)
    }
}

// Key rotation support
pub struct KeyManager {
    current_key: [u8; 32],
    previous_keys: Vec<[u8; 32]>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            current_key: SecureRandom::generate_bytes(32).try_into().unwrap(),
            previous_keys: Vec::new(),
        }
    }
    
    pub fn rotate_key(&mut self) {
        self.previous_keys.push(self.current_key);
        self.current_key = SecureRandom::generate_bytes(32).try_into().unwrap();
        
        // Keep only last 3 keys for decryption of old data
        if self.previous_keys.len() > 3 {
            self.previous_keys.remove(0);
        }
    }
    
    pub fn get_encryption(&self) -> CredentialEncryption {
        CredentialEncryption::new(&self.current_key)
    }
    
    pub fn try_decrypt_with_any_key(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        // Try current key first
        if let Ok(decrypted) = self.get_encryption().decrypt_credential_data(encrypted_data) {
            return Ok(decrypted);
        }
        
        // Try previous keys
        for key in &self.previous_keys {
            let encryption = CredentialEncryption::new(key);
            if let Ok(decrypted) = encryption.decrypt_credential_data(encrypted_data) {
                return Ok(decrypted);
            }
        }
        
        Err(SecurityError::DecryptionFailed.into())
    }
}
```

### 2.4 Rate Limiting and Abuse Prevention

#### **Advanced Rate Limiting**
```rust
use std::collections::HashMap;
use std::time::{SystemTime, Duration};

pub struct RateLimiter {
    limits: HashMap<String, RateLimit>,
    cleanup_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct RateLimit {
    pub max_requests: u32,
    pub window: Duration,
    pub current_requests: u32,
    pub window_start: SystemTime,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            limits: HashMap::new(),
            cleanup_interval: Duration::from_secs(60),
        }
    }
    
    pub fn check_rate_limit(&mut self, key: &str, limit: &RateLimit) -> Result<()> {
        let now = SystemTime::now();
        
        let entry = self.limits.entry(key.to_string()).or_insert_with(|| RateLimit {
            max_requests: limit.max_requests,
            window: limit.window,
            current_requests: 0,
            window_start: now,
        });
        
        // Reset window if expired
        if now.duration_since(entry.window_start).unwrap_or(Duration::ZERO) >= entry.window {
            entry.current_requests = 0;
            entry.window_start = now;
        }
        
        // Check limit
        if entry.current_requests >= entry.max_requests {
            security_event!(
                SecurityLevel::Medium,
                "Rate limit exceeded",
                key = key,
                current_requests = entry.current_requests,
                max_requests = entry.max_requests
            );
            return Err(SecurityError::RateLimitExceeded.into());
        }
        
        entry.current_requests += 1;
        Ok(())
    }
    
    pub fn check_ip_rate_limit(&mut self, ip: &str, endpoint: &str) -> Result<()> {
        let key = format!("ip:{}:{}", ip, endpoint);
        let limit = RateLimit {
            max_requests: 100,
            window: Duration::from_secs(60),
            current_requests: 0,
            window_start: SystemTime::now(),
        };
        
        self.check_rate_limit(&key, &limit)
    }
    
    pub fn check_user_rate_limit(&mut self, user_id: &str, operation: &str) -> Result<()> {
        let key = format!("user:{}:{}", user_id, operation);
        let limit = RateLimit {
            max_requests: 10,
            window: Duration::from_secs(60),
            current_requests: 0,
            window_start: SystemTime::now(),
        };
        
        self.check_rate_limit(&key, &limit)
    }
}
```

### 2.5 Security Monitoring and Auditing

#### **Security Event Logging**
```rust
use serde::{Serialize, Deserialize};
use log::{info, warn, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub timestamp: SystemTime,
    pub level: SecurityLevel,
    pub event_type: String,
    pub description: String,
    pub source_ip: Option<String>,
    pub user_id: Option<String>,
    pub details: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityLevel {
    Low,
    Medium,
    High,
    Critical,
}

pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log_security_event(event: SecurityEvent) {
        let log_level = match event.level {
            SecurityLevel::Low => log::Level::Info,
            SecurityLevel::Medium => log::Level::Warn,
            SecurityLevel::High => log::Level::Error,
            SecurityLevel::Critical => log::Level::Error,
        };
        
        let event_json = serde_json::to_string(&event).unwrap_or_default();
        
        log::log!(log_level, "SECURITY_EVENT: {}", event_json);
        
        // For critical events, also send to alerting system
        if matches!(event.level, SecurityLevel::Critical) {
            Self::send_alert(&event);
        }
    }
    
    fn send_alert(event: &SecurityEvent) {
        // Integration with alerting system
        // Could be Slack, PagerDuty, email, etc.
        warn!("CRITICAL SECURITY ALERT: {:?}", event);
    }
}

// Macro for easy security event logging
macro_rules! security_event {
    ($level:expr, $description:expr $(, $key:ident = $value:expr)*) => {
        {
            let mut details = std::collections::HashMap::new();
            $(
                details.insert(stringify!($key).to_string(), format!("{:?}", $value));
            )*
            
            let event = $crate::security::SecurityEvent {
                timestamp: std::time::SystemTime::now(),
                level: $level,
                event_type: "webauthn_operation".to_string(),
                description: $description.to_string(),
                source_ip: None, // Would be filled by middleware
                user_id: None,   // Would be filled by middleware
                details,
            };
            
            $crate::security::SecurityLogger::log_security_event(event);
        }
    };
}
```

## 3. Security Testing and Validation

### 3.1 Security Test Suite

#### **WebAuthn Security Tests**
```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_challenge_reuse_prevention() {
        let challenge_manager = ChallengeManager::new();
        let challenge = challenge_manager.generate_challenge(32);
        
        // Store challenge
        challenge_manager.store_challenge(
            challenge.clone(),
            None,
            ChallengeType::Attestation,
            Duration::from_secs(300),
        ).unwrap();
        
        // First verification should succeed
        let result1 = challenge_manager.verify_and_consume_challenge(
            &challenge,
            ChallengeType::Attestation,
        );
        assert!(result1.is_ok());
        
        // Second verification should fail
        let result2 = challenge_manager.verify_and_consume_challenge(
            &challenge,
            ChallengeType::Attestation,
        );
        assert!(result2.is_err());
    }
    
    #[test]
    fn test_origin_validation() {
        let validator = OriginValidator::new(
            vec!["https://example.com".to_string()],
            "example.com".to_string(),
        );
        
        // Valid origin
        assert!(validator.validate_origin("https://example.com").is_ok());
        
        // Invalid origin
        assert!(validator.validate_origin("https://evil.com").is_err());
        
        // Invalid RP ID
        assert!(validator.validate_rp_id("evil.com").is_err());
    }
    
    #[test]
    fn test_rate_limiting() {
        let mut rate_limiter = RateLimiter::new();
        let limit = RateLimit {
            max_requests: 2,
            window: Duration::from_secs(1),
            current_requests: 0,
            window_start: SystemTime::now(),
        };
        
        // First two requests should succeed
        assert!(rate_limiter.check_rate_limit("test_key", &limit).is_ok());
        assert!(rate_limiter.check_rate_limit("test_key", &limit).is_ok());
        
        // Third request should fail
        assert!(rate_limiter.check_rate_limit("test_key", &limit).is_err());
    }
}
```

### 3.2 Penetration Testing Checklist

#### **WebAuthn Specific Tests**
- [ ] Challenge replay attacks
- [ ] Origin spoofing attempts
- [ ] RP ID manipulation
- [ ] Attestation statement forgery
- [ ] Signature manipulation
- [ ] User verification bypass
- [ ] Credential enumeration
- [ ] Timing attacks

#### **General Security Tests**
- [ ] SQL injection
- [ ] XSS attacks
- [ ] CSRF attacks
- [ ] Rate limiting bypass
- [ ] Authentication bypass
- [ ] Privilege escalation
- [ ] Data exposure
- [ ] Denial of service

## 4. Incident Response Procedures

### 4.1 Security Incident Classification

#### **Critical Incidents**
- Successful credential theft
- Authentication bypass
- Data breach
- System compromise

#### **High Incidents**
- Brute force attacks
- Suspicious authentication patterns
- Rate limiting violations
- Configuration errors

#### **Medium Incidents**
- Failed authentication spikes
- Unusual user behavior
- Minor security misconfigurations

### 4.2 Response Procedures

#### **Immediate Response (0-15 minutes)**
1. **Isolation**: Block suspicious IPs/accounts
2. **Assessment**: Determine incident scope
3. **Notification**: Alert security team
4. **Preservation**: Collect evidence/logs

#### **Investigation (15-60 minutes)**
1. **Analysis**: Root cause analysis
2. **Impact**: Assess data/system impact
3. **Containment**: Prevent further damage
4. **Documentation**: Record all actions

#### **Recovery (1-4 hours)**
1. **Remediation**: Fix vulnerabilities
2. **Restoration**: Restore services
3. **Verification**: Test fixes
4. **Monitoring**: Enhanced monitoring

#### **Post-Incident (24-48 hours)**
1. **Review**: Incident review meeting
2. **Improvements**: Update procedures
3. **Training**: Team training
4. **Reporting**: Management reporting

This security implementation guide provides comprehensive security controls for the FIDO2/WebAuthn server, ensuring robust protection against common and advanced security threats while maintaining compliance with FIDO2 specifications.