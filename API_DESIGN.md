# FIDO2/WebAuthn API Design

## REST API Endpoints

### Base URL
```
https://your-domain.com/api/v1/webauthn
```

### 1. Registration Flow

#### Start Registration
```http
POST /api/v1/webauthn/register/start
Content-Type: application/json

{
  "username": "user@example.com",
  "display_name": "John Doe",
  "user_verification": "preferred", // "required", "preferred", "discouraged"
  "attestation": "direct", // "none", "indirect", "direct"
  "authenticator_selection": {
    "authenticator_attachment": "platform", // "platform", "cross-platform"
    "require_resident_key": false,
    "user_verification": "preferred"
  }
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "name": "Your Application",
      "id": "your-domain.com"
    },
    "user": {
      "id": "base64url-encoded-user-id",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7 // ES256
      },
      {
        "type": "public-key", 
        "alg": -257 // RS256
      }
    ],
    "timeout": 300000,
    "attestation": "direct",
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "extensions": {
      "credProps": true
    }
  },
  "session_id": "uuid-for-tracking-registration"
}
```

#### Finish Registration
```http
POST /api/v1/webauthn/register/finish
Content-Type: application/json

{
  "session_id": "uuid-from-start-registration",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-credential-id",
    "type": "public-key",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data"
    }
  }
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "credential_id": "base64url-encoded-credential-id",
  "user": {
    "id": "user-uuid",
    "username": "user@example.com",
    "display_name": "John Doe"
  },
  "authenticator_info": {
    "aaguid": "base64url-encoded-aaguid",
    "sign_count": 0,
    "backup_eligible": true,
    "backup_state": false,
    "user_verified": true
  }
}
```

### 2. Authentication Flow

#### Start Authentication
```http
POST /api/v1/webauthn/authenticate/start
Content-Type: application/json

{
  "username": "user@example.com",
  "user_verification": "preferred", // "required", "preferred", "discouraged"
  "allow_credentials": [ // Optional: specific credentials to use
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ]
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "publicKey": {
    "challenge": "base64url-encoded-challenge",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64url-encoded-credential-id",
        "transports": ["internal", "usb", "nfc", "ble"]
      }
    ],
    "userVerification": "preferred",
    "timeout": 300000,
    "extensions": {
      "credProps": true
    }
  },
  "session_id": "uuid-for-tracking-authentication"
}
```

#### Finish Authentication
```http
POST /api/v1/webauthn/authenticate/finish
Content-Type: application/json

{
  "session_id": "uuid-from-start-authentication",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-credential-id", 
    "type": "public-key",
    "response": {
      "authenticatorData": "base64url-encoded-authenticator-data",
      "clientDataJSON": "base64url-encoded-client-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle" // Optional
    }
  }
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "session_token": "jwt-or-opaque-session-token",
  "user": {
    "id": "user-uuid",
    "username": "user@example.com",
    "display_name": "John Doe"
  },
  "credential_info": {
    "credential_id": "base64url-encoded-credential-id",
    "sign_count": 5,
    "user_verified": true,
    "backup_state": true
  },
  "expires_in": 3600
}
```

### 3. Credential Management

#### List User Credentials
```http
GET /api/v1/webauthn/credentials
Authorization: Bearer <session-token>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "credentials": [
    {
      "id": "base64url-encoded-credential-id",
      "name": "iPhone 14 Pro",
      "type": "public-key",
      "created_at": "2024-01-15T10:30:00Z",
      "last_used_at": "2024-01-20T14:22:00Z",
      "transports": ["internal"],
      "backup_eligible": true,
      "backup_state": true,
      "user_verified": true,
      "sign_count": 15
    }
  ]
}
```

#### Delete Credential
```http
DELETE /api/v1/webauthn/credentials/{credential_id}
Authorization: Bearer <session-token>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "message": "Credential deleted successfully"
}
```

#### Update Credential Name
```http
PUT /api/v1/webauthn/credentials/{credential_id}
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "name": "Updated Device Name"
}
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "name": "Updated Device Name"
  }
}
```

### 4. User Management

#### Get User Profile
```http
GET /api/v1/webauthn/user/profile
Authorization: Bearer <session-token>
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "user": {
    "id": "user-uuid",
    "username": "user@example.com",
    "display_name": "John Doe",
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-20T14:22:00Z"
  },
  "credentials_count": 3,
  "last_authentication": "2024-01-20T14:22:00Z"
}
```

#### Update User Profile
```http
PUT /api/v1/webauthn/user/profile
Authorization: Bearer <session-token>
Content-Type: application/json

{
  "display_name": "John Smith"
}
```

### 5. Health and Status

#### Health Check
```http
GET /api/v1/webauthn/health
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "healthy",
  "timestamp": "2024-01-20T15:30:00Z",
  "version": "1.0.0",
  "webauthn_version": "0.5.0",
  "database": "connected"
}
```

## Data Flow

### Registration Flow
1. Client requests registration start
2. Server generates challenge and user entity
3. Server stores challenge state with TTL
4. Client creates credential with authenticator
5. Client sends attestation to server
6. Server verifies attestation and stores credential
7. Server returns success response

### Authentication Flow
1. Client requests authentication start
2. Server generates challenge for user credentials
3. Server stores challenge state with TTL
4. Client authenticates with stored credential
5. Client sends assertion to server
6. Server verifies assertion and signature
7. Server updates credential usage and creates session
8. Server returns session token

## Security Headers

All responses should include:
```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## Error Responses

### Standard Error Format
```http
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request parameters",
    "details": {
      "field": "username",
      "reason": "Username is required"
    }
  },
  "timestamp": "2024-01-20T15:30:00Z",
  "request_id": "uuid-for-tracking"
}
```

### Common Error Codes
- `INVALID_REQUEST`: Malformed request
- `INVALID_CREDENTIAL`: Credential verification failed
- `INVALID_CHALLENGE`: Challenge expired or invalid
- `USER_NOT_FOUND`: User does not exist
- `CREDENTIAL_EXISTS`: Credential already registered
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Server error