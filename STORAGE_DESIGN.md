# FIDO2/WebAuthn Storage Design

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    active BOOLEAN DEFAULT true
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
```

### Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL, -- Raw credential ID
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid BYTEA,
    attestation_type VARCHAR(50),
    attestation_trust_path JSONB,
    transports JSONB, -- ["internal", "usb", "nfc", "ble"]
    backup_eligible BOOLEAN DEFAULT false,
    backed_up BOOLEAN DEFAULT false,
    device_name VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    clone_warning BOOLEAN DEFAULT false,
    active BOOLEAN DEFAULT true
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(active);
```

### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id UUID UNIQUE NOT NULL DEFAULT gen_random_uuid(),
    challenge_data BYTEA NOT NULL, -- Raw challenge bytes
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' | 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB -- Additional challenge metadata
);

CREATE INDEX idx_challenges_challenge_id ON challenges(challenge_id);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_type ON challenges(challenge_type);
```

### Sessions Table
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    active BOOLEAN DEFAULT true
);

CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

### Audit Log Table
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, -- 'register', 'authenticate', 'credential_delete'
    credential_id BYTEA,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_code VARCHAR(50),
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

## Data Models (Rust/Diesel)

### User Model
```rust
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
    pub email: Option<String>,
}
```

### Credential Model
```rust
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_type: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub aaguid: Option<Vec<u8>>,
    pub attestation_type: Option<String>,
    pub attestation_trust_path: Option<serde_json::Value>,
    pub transports: Option<serde_json::Value>,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub device_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used: Option<DateTime<Utc>>,
    pub clone_warning: bool,
    pub active: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_type: String,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub aaguid: Option<Vec<u8>>,
    pub attestation_type: Option<String>,
    pub attestation_trust_path: Option<serde_json::Value>,
    pub transports: Option<serde_json::Value>,
    pub backup_eligible: bool,
    pub backed_up: bool,
    pub device_name: Option<String>,
}
```

### Challenge Model
```rust
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: Uuid,
    pub challenge_data: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge_id: Uuid,
    pub challenge_data: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}
```

## Storage Security Requirements

### 1. Encryption at Rest
- All sensitive data encrypted using AES-256-GCM
- Database-level encryption for credential data
- Key management using secure key store

### 2. Data Integrity
- Cryptographic hashes for stored credentials
- Digital signatures for audit logs
- Database constraints and validations

### 3. Access Control
- Row-level security for user data
- Database user permissions
- Connection encryption (TLS)

### 4. Data Retention
- Challenge data: 5 minutes (auto-cleanup)
- Session data: Configurable (default 24 hours)
- Audit logs: 1 year (configurable)
- Inactive credentials: 90 days soft delete

## Performance Considerations

### 1. Indexing Strategy
- Primary keys on all tables
- Foreign key indexes
- Query-specific indexes
- Partial indexes for active records

### 2. Connection Pooling
- Connection pool size: 10-20 connections
- Connection timeout: 30 seconds
- Idle timeout: 10 minutes

### 3. Caching Strategy
- Redis for session storage
- In-memory cache for frequently accessed credentials
- Challenge cache for fast lookups

### 4. Cleanup Jobs
- Expired challenge cleanup (every 1 minute)
- Session cleanup (every 5 minutes)
- Audit log rotation (daily)

## Backup and Recovery

### 1. Database Backups
- Daily full backups
- Hourly incremental backups
- Point-in-time recovery capability

### 2. Disaster Recovery
- Multi-region replication
- Automated failover
- Recovery time objective: < 1 hour
- Recovery point objective: < 5 minutes

### 3. Data Migration
- Schema versioning with migrations
- Backward compatibility support
- Data validation during migration