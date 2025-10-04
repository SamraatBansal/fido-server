# FIDO2/WebAuthn API Design

## REST API Endpoints

### Health Check
```
GET /health
Response: {"status": "ok", "timestamp": "2024-01-01T00:00:00Z"}
```

### Registration Flow

#### 1. Initiate Registration
```
POST /api/v1/register/start
Content-Type: application/json

Request Body:
{
  "username": "user@example.com",
  "display_name": "John Doe",
  "user_verification": "preferred", // "required" | "preferred" | "discouraged"
  "attestation": "direct" // "none" | "indirect" | "direct"
}

Response Body:
{
  "challenge_id": "uuid-v4",
  "public_key": {
    "challenge": "base64url-encoded-challenge",
    "rp": {
      "name": "FIDO Server",
      "id": "example.com"
    },
    "user": {
      "id": "base64url-encoded-user-id",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "pubKeyCredParams": [
      {"type": "public-key", "alg": -7},  // ES256
      {"type": "public-key", "alg": -257} // RS256
    ],
    "timeout": 300000,
    "attestation": "direct",
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "preferred",
      "requireResidentKey": false
    }
  }
}
```

#### 2. Complete Registration
```
POST /api/v1/register/finish
Content-Type: application/json

Request Body:
{
  "challenge_id": "uuid-v4",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data"
    },
    "type": "public-key"
  }
}

Response Body:
{
  "credential_id": "base64url-encoded-credential-id",
  "user_id": "uuid-v4",
  "created_at": "2024-01-01T00:00:00Z",
  "authenticator_info": {
    "aaguid": "base64url-encoded-aaguid",
    "sign_count": 0,
    "clone_warning": false
  }
}
```

### Authentication Flow

#### 1. Initiate Authentication
```
POST /api/v1/authenticate/start
Content-Type: application/json

Request Body:
{
  "username": "user@example.com", // Optional for usernameless auth
  "user_verification": "preferred"
}

Response Body:
{
  "challenge_id": "uuid-v4",
  "public_key": {
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
    "rpId": "example.com"
  }
}
```

#### 2. Complete Authentication
```
POST /api/v1/authenticate/finish
Content-Type: application/json

Request Body:
{
  "challenge_id": "uuid-v4",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "authenticatorData": "base64url-encoded-auth-data",
      "clientDataJSON": "base64url-encoded-client-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle" // Optional
    },
    "type": "public-key"
  }
}

Response Body:
{
  "user_id": "uuid-v4",
  "username": "user@example.com",
  "authenticated_at": "2024-01-01T00:00:00Z",
  "authenticator_info": {
    "sign_count": 123,
    "clone_warning": false
  },
  "session_token": "jwt-session-token"
}
```

### Credential Management

#### List User Credentials
```
GET /api/v1/credentials
Authorization: Bearer <session-token>

Response Body:
{
  "credentials": [
    {
      "credential_id": "base64url-encoded-id",
      "name": "iPhone 14 Pro",
      "created_at": "2024-01-01T00:00:00Z",
      "last_used": "2024-01-01T12:00:00Z",
      "transports": ["internal"],
      "backup_eligible": true,
      "backed_up": true
    }
  ]
}
```

#### Delete Credential
```
DELETE /api/v1/credentials/{credential_id}
Authorization: Bearer <session-token>

Response Body:
{
  "message": "Credential deleted successfully"
}
```

## Data Flow Architecture

### Registration Flow
```
Client → /register/start → Challenge Generation → Store Challenge → Return PublicKeyCredentialCreationOptions
Client → Authenticator → Create Credential → /register/finish → Verify Attestation → Store Credential → Return Success
```

### Authentication Flow
```
Client → /authenticate/start → Challenge Generation → Get User Credentials → Return PublicKeyCredentialRequestOptions
Client → Authenticator → Sign Challenge → /authenticate/finish → Verify Assertion → Update Sign Count → Return Session
```

## Security Headers

All responses must include:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
```

## Error Responses

### Standard Error Format
```json
{
  "error": {
    "code": "INVALID_CHALLENGE",
    "message": "The provided challenge is invalid or expired",
    "details": {
      "challenge_id": "uuid-v4",
      "expired_at": "2024-01-01T00:05:00Z"
    }
  }
}
```

### Error Codes
- `INVALID_CHALLENGE`: Challenge not found or expired
- `INVALID_CREDENTIAL`: Credential verification failed
- `USER_NOT_FOUND`: User does not exist
- `CREDENTIAL_EXISTS`: Credential already registered
- `INVALID_ATTESTATION`: Attestation verification failed
- `INVALID_ASSERTION`: Assertion verification failed
- `RATE_LIMIT_EXCEEDED`: Too many requests
- `INVALID_ORIGIN`: Origin validation failed
- `UNSUPPORTED_AUTHENTICATOR`: Authenticator not supported