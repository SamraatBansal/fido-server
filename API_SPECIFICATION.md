# FIDO2/WebAuthn Server - API Specification

## Overview

This document provides a detailed API specification for the FIDO2/WebAuthn Relying Party Server, aligned with FIDO Alliance conformance test requirements and WebAuthn specification.

## 1. API Architecture

### 1.1 Base Configuration
- **Base URL**: `https://rp.example.com/webauthn`
- **Protocol**: HTTPS only (TLS 1.2+ required)
- **Content-Type**: `application/json`
- **Character Encoding**: UTF-8
- **API Version**: v1

### 1.2 Authentication
- **Method**: Bearer Token (JWT) for admin operations
- **User Authentication**: WebAuthn-based session management
- **Rate Limiting**: 100 requests per minute per IP

### 1.3 Response Format
All responses follow a consistent structure:

```json
{
  "status": "ok|error",
  "data": { ... }, // Present only on success
  "error": {       // Present only on error
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": { ... } // Optional additional error details
  }
}
```

## 2. Registration API

### 2.1 Start Registration Ceremony

**Endpoint**: `POST /webauthn/register/challenge`

**Description**: Initiates the WebAuthn registration ceremony by generating a challenge and returning credential creation options.

#### Request
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|indirect|direct|enterprise",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged"
  },
  "extensions": {
    "credProps": true,
    "exts": true
  }
}
```

#### Request Validation
- `username`: Required, 3-255 characters, valid email format
- `displayName`: Required, 1-255 characters, no control characters
- `userVerification`: Optional, defaults to "preferred"
- `attestation`: Optional, defaults to "none"
- `authenticatorSelection`: Optional, authenticator selection criteria
- `extensions`: Optional, WebAuthn extensions

#### Response
```json
{
  "status": "ok",
  "data": {
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
      {"type": "public-key", "alg": -7},   // ES256
      {"type": "public-key", "alg": -257}, // RS256
      {"type": "public-key", "alg": -8},   // EdDSA
      {"type": "public-key", "alg": -37}   // ES384
    ],
    "timeout": 60000,
    "attestation": "none",
    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "extensions": {
      "credProps": true
    }
  }
}
```

#### Response Validation
- `challenge`: Base64URL encoded, minimum 16 bytes when decoded
- `rp.id`: Must match effective domain
- `user.id`: Base64URL encoded, unique per user
- `pubKeyCredParams`: Must include supported algorithms
- `timeout`: 30000-120000 milliseconds

#### Error Responses
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request format",
    "details": {
      "field": "username",
      "reason": "Invalid email format"
    }
  }
}
```

**Error Codes**:
- `INVALID_REQUEST`: Malformed request
- `USER_EXISTS`: User already registered
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Server error

### 2.2 Complete Registration Ceremony

**Endpoint**: `POST /webauthn/register/verify`

**Description**: Completes the WebAuthn registration ceremony by verifying the attestation response and storing the credential.

#### Request
```json
{
  "username": "user@example.com",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data",
      "transports": ["internal", "usb", "nfc", "ble"]
    },
    "type": "public-key",
    "clientExtensionResults": {
      "credProps": {
        "rk": true
      }
    }
  }
}
```

#### Request Validation
- `credential.id`: Base64URL encoded, max 1024 bytes
- `credential.type`: Must be "public-key"
- `credential.response.attestationObject`: Valid CBOR-encoded attestation
- `credential.response.clientDataJSON`: Valid JSON with required fields
- `credential.response.transports`: Optional, valid transport values

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-encoded-credential-id",
    "signCount": 0,
    "aaguid": "base64url-encoded-aaguid",
    "transports": ["internal"],
    "attestationType": "packed",
    "credProps": {
      "rk": true
    }
  }
}
```

#### Response Validation
- `credentialId`: Matches request credential ID
- `signCount`: Initial counter value (usually 0)
- `aaguid`: Authenticator AAGUID if available
- `transports`: Supported transports
- `attestationType`: Attestation format used

#### Error Responses
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_ATTESTATION",
    "message": "Attestation verification failed",
    "details": {
      "reason": "Invalid signature",
      "format": "packed"
    }
  }
}
```

**Error Codes**:
- `INVALID_ATTESTATION`: Attestation verification failed
- `INVALID_CHALLENGE`: Challenge mismatch or expired
- `INVALID_CLIENT_DATA`: Client data validation failed
- `INVALID_AUTHENTICATOR_DATA`: Authenticator data validation failed
- `CREDENTIAL_EXISTS`: Credential ID already exists
- `USER_NOT_FOUND`: User not found
- `INTERNAL_ERROR`: Server error

## 3. Authentication API

### 3.1 Start Authentication Ceremony

**Endpoint**: `POST /webauthn/authenticate/challenge`

**Description**: Initiates the WebAuthn authentication ceremony by generating a challenge and returning credential request options.

#### Request
```json
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "extensions": {
    "credProps": true
  }
}
```

#### Request Validation
- `username`: Required, existing user
- `userVerification`: Optional, defaults to "preferred"
- `allowCredentials`: Optional, specific credentials to allow
- `extensions`: Optional, WebAuthn extensions

#### Response
```json
{
  "status": "ok",
  "data": {
    "challenge": "base64url-encoded-challenge",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64url-encoded-credential-id",
        "transports": ["internal", "usb"]
      }
    ],
    "userVerification": "preferred",
    "timeout": 60000,
    "rpId": "example.com",
    "extensions": {
      "credProps": true
    }
  }
}
```

#### Response Validation
- `challenge`: Base64URL encoded, minimum 16 bytes when decoded
- `allowCredentials`: User's existing credentials or empty for discoverable
- `userVerification`: User verification requirement
- `rpId`: Relying Party ID
- `timeout`: 30000-120000 milliseconds

#### Error Responses
```json
{
  "status": "error",
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "User not found",
    "details": {
      "username": "user@example.com"
    }
  }
}
```

**Error Codes**:
- `USER_NOT_FOUND`: User not found
- `NO_CREDENTIALS`: User has no registered credentials
- `INVALID_REQUEST`: Malformed request
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Server error

### 3.2 Complete Authentication Ceremony

**Endpoint**: `POST /webauthn/authenticate/verify`

**Description**: Completes the WebAuthn authentication ceremony by verifying the assertion response and establishing a session.

#### Request
```json
{
  "username": "user@example.com",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "authenticatorData": "base64url-encoded-auth-data",
      "clientDataJSON": "base64url-encoded-client-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle"
    },
    "type": "public-key",
    "clientExtensionResults": {
      "credProps": {
        "rk": true
      }
    }
  }
}
```

#### Request Validation
- `credential.id`: Base64URL encoded, existing credential
- `credential.type`: Must be "public-key"
- `credential.response.authenticatorData`: Valid authenticator data
- `credential.response.clientDataJSON`: Valid JSON with required fields
- `credential.response.signature`: Valid signature over assertion data
- `credential.response.userHandle`: Base64URL encoded user ID

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-encoded-credential-id",
    "signCount": 42,
    "userVerified": true,
    "authenticatorInfo": {
      "aaguid": "base64url-encoded-aaguid",
      "transports": ["internal"]
    },
    "sessionToken": "jwt-session-token",
    "expiresIn": 3600
  }
}
```

#### Response Validation
- `credentialId`: Matches request credential ID
- `signCount`: Updated counter value
- `userVerified`: User verification status
- `sessionToken`: JWT for session management
- `expiresIn`: Session expiration in seconds

#### Error Responses
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_ASSERTION",
    "message": "Assertion verification failed",
    "details": {
      "reason": "Invalid signature",
      "credentialId": "base64url-encoded-credential-id"
    }
  }
}
```

**Error Codes**:
- `INVALID_ASSERTION`: Assertion verification failed
- `INVALID_CHALLENGE`: Challenge mismatch or expired
- `INVALID_CLIENT_DATA`: Client data validation failed
- `INVALID_AUTHENTICATOR_DATA`: Authenticator data validation failed
- `CREDENTIAL_NOT_FOUND`: Credential not found
- `REPLAY_DETECTED`: Replay attack detected
- `USER_NOT_FOUND`: User not found
- `INTERNAL_ERROR`: Server error

## 4. Credential Management API

### 4.1 List User Credentials

**Endpoint**: `GET /webauthn/credentials`

**Description**: Retrieves all credentials registered for the authenticated user.

#### Request Headers
```
Authorization: Bearer <session-token>
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentials": [
      {
        "credentialId": "base64url-encoded-credential-id",
        "name": "Security Key",
        "createdAt": "2024-01-01T12:00:00Z",
        "lastUsed": "2024-01-15T14:30:00Z",
        "signCount": 42,
        "transports": ["internal", "usb"],
        "isBackup": false,
        "aaguid": "base64url-encoded-aaguid"
      }
    ]
  }
}
```

### 4.2 Delete Credential

**Endpoint**: `DELETE /webauthn/credentials/{credentialId}`

**Description**: Deletes a specific credential for the authenticated user.

#### Request Headers
```
Authorization: Bearer <session-token>
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-encoded-credential-id",
    "deleted": true
  }
}
```

### 4.3 Update Credential Name

**Endpoint**: `PUT /webauthn/credentials/{credentialId}/name`

**Description**: Updates the display name of a credential.

#### Request Headers
```
Authorization: Bearer <session-token>
```

#### Request
```json
{
  "name": "My Security Key"
}
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-encoded-credential-id",
    "name": "My Security Key"
  }
}
```

## 5. User Management API

### 5.1 Get User Profile

**Endpoint**: `GET /webauthn/user/profile`

**Description**: Retrieves the authenticated user's profile information.

#### Request Headers
```
Authorization: Bearer <session-token>
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "id": "uuid-user-id",
    "username": "user@example.com",
    "displayName": "John Doe",
    "createdAt": "2024-01-01T12:00:00Z",
    "lastLogin": "2024-01-15T14:30:00Z",
    "credentialCount": 2
  }
}
```

### 5.2 Update User Profile

**Endpoint**: `PUT /webauthn/user/profile`

**Description**: Updates the authenticated user's profile information.

#### Request Headers
```
Authorization: Bearer <session-token>
```

#### Request
```json
{
  "displayName": "John Smith"
}
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "id": "uuid-user-id",
    "username": "user@example.com",
    "displayName": "John Smith",
    "updatedAt": "2024-01-15T15:00:00Z"
  }
}
```

## 6. Admin API

### 6.1 Get Server Information

**Endpoint**: `GET /webauthn/admin/info`

**Description**: Retrieves server configuration and status information.

#### Request Headers
```
Authorization: Bearer <admin-token>
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "version": "1.0.0",
    "rpId": "example.com",
    "rpName": "FIDO Server",
    "supportedAlgorithms": [
      {"alg": -7, "name": "ES256"},
      {"alg": -257, "name": "RS256"},
      {"alg": -8, "name": "EdDSA"}
    ],
    "attestationFormats": ["none", "packed", "fido-u2f"],
    "userVerification": ["required", "preferred", "discouraged"],
    "uptime": 86400,
    "totalUsers": 1000,
    "totalCredentials": 2500
  }
}
```

### 6.2 Get User Statistics

**Endpoint**: `GET /webauthn/admin/stats/users`

**Description**: Retrieves user registration and usage statistics.

#### Request Headers
```
Authorization: Bearer <admin-token>
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "totalUsers": 1000,
    "activeUsers": 850,
    "usersWithCredentials": 950,
    "newUsersToday": 5,
    "newUsersThisWeek": 35,
    "newUsersThisMonth": 120
  }
}
```

### 6.3 Get Credential Statistics

**Endpoint**: `GET /webauthn/admin/stats/credentials`

**Description**: Retrieves credential registration and usage statistics.

#### Request Headers
```
Authorization: Bearer <admin-token>
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "totalCredentials": 2500,
    "activeCredentials": 2300,
    "backupCredentials": 500,
    "newCredentialsToday": 15,
    "newCredentialsThisWeek": 85,
    "newCredentialsThisMonth": 320,
    "credentialsByType": {
      "platform": 1200,
      "cross-platform": 1300
    },
    "credentialsByTransport": {
      "internal": 1500,
      "usb": 800,
      "nfc": 150,
      "ble": 50
    }
  }
}
```

## 7. Health Check API

### 7.1 Health Check

**Endpoint**: `GET /health`

**Description**: Basic health check endpoint.

#### Response
```json
{
  "status": "ok",
  "data": {
    "healthy": true,
    "timestamp": "2024-01-15T15:00:00Z"
  }
}
```

### 7.2 Detailed Health Check

**Endpoint**: `GET /health/detailed`

**Description**: Detailed health check including database and external dependencies.

#### Response
```json
{
  "status": "ok",
  "data": {
    "healthy": true,
    "timestamp": "2024-01-15T15:00:00Z",
    "checks": {
      "database": {
        "healthy": true,
        "responseTime": 5
      },
      "memory": {
        "healthy": true,
        "usage": "45%"
      },
      "disk": {
        "healthy": true,
        "usage": "30%"
      }
    }
  }
}
```

## 8. Error Handling

### 8.1 Standard Error Format

All error responses follow this format:
```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": {
      "field": "field_name",
      "reason": "specific error reason",
      "timestamp": "2024-01-15T15:00:00Z",
      "requestId": "uuid-request-id"
    }
  }
}
```

### 8.2 HTTP Status Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request format
- `401 Unauthorized`: Authentication required or failed
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource conflict (e.g., duplicate)
- `422 Unprocessable Entity`: Valid format but semantic error
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### 8.3 Error Codes Reference

#### Registration Errors
- `INVALID_REQUEST`: Malformed registration request
- `USER_EXISTS`: User already registered
- `INVALID_ATTESTATION`: Attestation verification failed
- `INVALID_CHALLENGE`: Challenge mismatch or expired
- `INVALID_CLIENT_DATA`: Client data validation failed
- `INVALID_AUTHENTICATOR_DATA`: Authenticator data validation failed
- `CREDENTIAL_EXISTS`: Credential ID already exists
- `UNSUPPORTED_ALGORITHM`: Unsupported signature algorithm

#### Authentication Errors
- `USER_NOT_FOUND`: User not found
- `NO_CREDENTIALS`: User has no registered credentials
- `INVALID_ASSERTION`: Assertion verification failed
- `CREDENTIAL_NOT_FOUND`: Credential not found
- `REPLAY_DETECTED`: Replay attack detected
- `INVALID_SIGNATURE`: Signature verification failed
- `COUNTER_ERROR`: Counter validation failed

#### General Errors
- `RATE_LIMITED`: Too many requests
- `INTERNAL_ERROR`: Internal server error
- `SERVICE_UNAVAILABLE`: Service temporarily unavailable
- `INVALID_TOKEN`: Invalid or expired token
- `INSUFFICIENT_PERMISSIONS`: Insufficient permissions

## 9. Security Headers

All API responses include these security headers:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## 10. CORS Configuration

For WebAuthn API endpoints:
```
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 86400
Access-Control-Allow-Credentials: true
```

## 11. Rate Limiting

### 11.1 Rate Limit Rules

- **Registration endpoints**: 10 requests per minute per IP
- **Authentication endpoints**: 30 requests per minute per IP
- **Credential management**: 20 requests per minute per user
- **Admin endpoints**: 100 requests per minute per admin token

### 11.2 Rate Limit Headers

Rate limited responses include:
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1642248000
```

## 12. API Versioning

### 12.1 Version Strategy
- URL path versioning: `/webauthn/v1/...`
- Current version: v1
- Backward compatibility maintained for at least 2 versions

### 12.2 Version Deprecation
- 6 months deprecation notice
- Sunset after 12 months
- Migration guides provided

This API specification provides a comprehensive foundation for implementing a FIDO2/WebAuthn Relying Party Server that meets FIDO Alliance conformance requirements and supports comprehensive testing.