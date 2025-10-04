# FIDO2/WebAuthn Storage Requirements

## Database Schema Design

### PostgreSQL Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Credentials table
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports JSONB NOT NULL DEFAULT '[]',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    device_name VARCHAR(255),
    metadata JSONB DEFAULT '{}'
);

-- Challenge storage (temporary, with TTL)
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_data BYTEA NOT NULL,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    credential_id BYTEA REFERENCES credentials(credential_id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT
);

-- Audit log for security events
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL, -- 'registration', 'authentication', 'credential_deleted'
    credential_id BYTEA REFERENCES credentials(credential_id),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_details TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
```

## Diesel ORM Models

```rust
// src/db/models.rs
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transports: serde_json::Value,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub device_name: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transports: serde_json::Value,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub device_name: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge_data: Vec<u8>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub user_id: Uuid,
    pub challenge_data: Vec<u8>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = crate::schema::sessions)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub credential_id: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::sessions)]
pub struct NewSession {
    pub user_id: Uuid,
    pub session_token: String,
    pub credential_id: Option<Vec<u8>>,
    pub expires_at: DateTime<Utc>,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = crate::schema::audit_log)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub credential_id: Option<Vec<u8>>,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_details: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::audit_log)]
pub struct NewAuditLog {
    pub user_id: Option<Uuid>,
    pub event_type: String,
    pub credential_id: Option<Vec<u8>>,
    pub ip_address: Option<std::net::IpAddr>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub error_details: Option<String>,
}
```

## Storage Security Requirements

### 1. Encryption at Rest
```rust
// src/utils/encryption.rs
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use rand::Rng;

pub struct CredentialEncryption {
    cipher: Aes256Gcm,
}

impl CredentialEncryption {
    pub fn new(key: &[u8; 32]) -> Self {
        let key = Key::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        Self { cipher }
    }

    pub fn encrypt_credential_data(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let mut rng = rand::thread_rng();
        let nonce_bytes: [u8; 12] = rng.gen();
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let mut encrypted = self.cipher.encrypt(nonce, data)
            .map_err(|_| EncryptionError::EncryptionFailed)?;
        
        // Prepend nonce to encrypted data
        encrypted.splice(0..0, nonce_bytes.to_vec());
        Ok(encrypted)
    }

    pub fn decrypt_credential_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if encrypted_data.len() < 12 {
            return Err(EncryptionError::InvalidData);
        }

        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| EncryptionError::DecryptionFailed)
    }
}
```

### 2. Key Management
```rust
// src/config/keys.rs
use std::fs;
use std::path::Path;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptionKeys {
    pub credential_encryption_key: String, // Base64 encoded
    pub session_signing_key: String,       // Base64 encoded
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl EncryptionKeys {
    pub fn load_or_generate<P: AsRef<Path>>(path: P) -> Result<Self, KeyError> {
        if path.as_ref().exists() {
            let content = fs::read_to_string(path)?;
            let keys: EncryptionKeys = serde_json::from_str(&content)?;
            Ok(keys)
        } else {
            let keys = Self::generate();
            let content = serde_json::to_string_pretty(&keys)?;
            fs::write(path, content)?;
            Ok(keys)
        }
    }

    pub fn generate() -> Self {
        let credential_key = Self::generate_random_key();
        let signing_key = Self::generate_random_key();
        
        Self {
            credential_encryption_key: credential_key,
            session_signing_key: signing_key,
            created_at: chrono::Utc::now(),
        }
    }

    fn generate_random_key() -> String {
        let mut key = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        base64::encode(key)
    }

    pub fn credential_key_bytes(&self) -> Result<[u8; 32], KeyError> {
        let decoded = base64::decode(&self.credential_encryption_key)?;
        decoded.try_into()
            .map_err(|_| KeyError::InvalidKeyLength)
    }
}
```

## In-Memory Storage (for challenges)

```rust
// src/storage/memory.rs
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::time::interval;
use uuid::Uuid;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeData {
    pub user_id: Uuid,
    pub challenge_type: ChallengeType,
    pub data: Vec<u8>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

pub struct MemoryChallengeStore {
    challenges: HashMap<String, ChallengeData>,
    cleanup_interval: Duration,
}

impl MemoryChallengeStore {
    pub fn new() -> Self {
        let store = Self {
            challenges: HashMap::new(),
            cleanup_interval: Duration::from_secs(60),
        };
        
        // Start cleanup task
        store.start_cleanup_task();
        store
    }

    pub fn store_challenge(&mut self, challenge_id: String, data: ChallengeData) {
        self.challenges.insert(challenge_id, data);
    }

    pub fn get_challenge(&mut self, challenge_id: &str) -> Option<ChallengeData> {
        let challenge = self.challenges.get(challenge_id)?.clone();
        
        // Remove challenge after retrieval (one-time use)
        self.challenges.remove(challenge_id);
        
        // Check if expired
        if challenge.expires_at > Instant::now() {
            Some(challenge)
        } else {
            None
        }
    }

    fn start_cleanup_task(&self) {
        let challenges = self.challenges.clone();
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let now = Instant::now();
                challenges.retain(|_, challenge| challenge.expires_at > now);
            }
        });
    }
}
```

## Data Retention and Cleanup

### 1. Challenge Cleanup
- Automatic cleanup every 60 seconds
- Challenges expire after 10 minutes
- One-time use (removed after retrieval)

### 2. Session Management
- Sessions expire after configurable TTL (default 1 hour)
- Sliding expiration on activity
- Cleanup job runs hourly

### 3. Audit Log Retention
- Keep audit logs for minimum 1 year
- Archive old logs to cold storage
- Compress archived logs

### 4. Backup Strategy
```rust
// src/utils/backup.rs
pub struct BackupManager {
    db_pool: Arc<DbPool>,
    backup_path: PathBuf,
}

impl BackupManager {
    pub async fn create_backup(&self) -> Result<BackupResult, BackupError> {
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_file = self.backup_path.join(format!("backup_{}.sql", timestamp));
        
        // Use pg_dump for consistent backup
        let output = tokio::process::Command::new("pg_dump")
            .arg("--format=custom")
            .arg("--compress=9")
            .arg("--file")
            .arg(&backup_file)
            .arg(&self.database_url)
            .output()
            .await?;
            
        if !output.status.success() {
            return Err(BackupError::DumpFailed(String::from_utf8_lossy(&output.stderr)));
        }
        
        Ok(BackupResult {
            file_path: backup_file,
            size: backup_file.metadata()?.len(),
            created_at: chrono::Utc::now(),
        })
    }
}
```

## Performance Considerations

### 1. Database Indexing
- Primary keys on all UUID columns
- Index on credential_id for fast lookups
- Composite indexes for user+credential queries
- TTL indexes for challenge cleanup

### 2. Connection Pooling
```rust
// src/db/connection.rs
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::pg::PgConnection;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

pub fn create_pool(database_url: &str) -> Result<DbPool, DbError> {
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .max_size(15)
        .min_idle(Some(5))
        .connection_timeout(Duration::from_secs(30))
        .idle_timeout(Some(Duration::from_secs(600)))
        .max_lifetime(Some(Duration::from_secs(1800)))
        .build(manager)?;
    
    Ok(pool)
}
```

### 3. Caching Strategy
- Cache user credentials in memory for frequent access
- Use Redis for distributed caching if needed
- Implement cache invalidation on credential changes

## Compliance Requirements

### 1. Data Protection
- GDPR compliance for user data
- Right to be forgotten (credential deletion)
- Data minimization principles

### 2. Audit Requirements
- Immutable audit logs
- Tamper-evident storage
- Regular integrity checks

### 3. Security Standards
- ISO 27001 alignment
- SOC 2 Type II compliance
- FIPS 140-2 validated cryptography