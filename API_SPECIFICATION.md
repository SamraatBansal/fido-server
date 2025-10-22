# FIDO2/WebAuthn Server - API Specification

## Overview

This document provides a detailed API specification for the FIDO2/WebAuthn Relying Party Server, aligned with FIDO Alliance conformance test requirements and REST API best practices.

## 1. API Architecture

### 1.1 Base Configuration

- **Base URL**: `https://rp.example.com/api/v1`
- **Protocol**: HTTPS only (TLS 1.3 required)
- **Content-Type**: `application/json`
- **Character Encoding**: UTF-8
- **API Version**: v1 (versioned through URL path)

### 1.2 Authentication

- **Method**: Bearer Token (JWT) for administrative operations
- **Session Management**: Secure HTTP-only cookies for user sessions
- **CORS**: Configured for specific origins only

### 1.3 Rate Limiting

- **Registration**: 10 requests per minute per IP
- **Authentication**: 30 requests per minute per IP
- **Administrative**: 5 requests per minute per token

## 2. Registration API

### 2.1 Registration Challenge

#### Endpoint
```
POST /api/v1/registration/challenge
```

#### Request Headers
```
Content-Type: application/json
Accept: application/json
X-Requested-With: XMLHttpRequest
```

#### Request Body
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise|indirect",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required",
    "residentKey": "required|preferred|discouraged"
  },
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "required"
    }
  }
}
```

#### Request Validation
- `username`: Required, valid email format, 3-255 characters
- `displayName`: Required, 1-255 characters, no control characters
- `userVerification`: Optional, enum value, defaults to "preferred"
- `attestation`: Optional, enum value, defaults to "none"
- `authenticatorSelection`: Optional, object with specific constraints
- `extensions`: Optional, object with supported extensions

#### Response (200 OK)
```json
{
  "status": "ok",
  "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
  "rp": {
    "name": "Example Relying Party",
    "id": "example.com"
  },
  "user": {
    "id": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    },
    {
      "type": "public-key",
      "alg": -257
    },
    {
      "type": "public-key",
      "alg": -37
    },
    {
      "type": "public-key",
      "alg": -8
    }
  ],
  "timeout": 60000,
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "ZXhpc3RpbmctY3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "cross-platform",
    "requireResidentKey": false,
    "userVerification": "preferred",
    "residentKey": "discouraged"
  },
  "attestation": "none",
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "preferred"
    }
  }
}
```

#### Error Responses

**400 Bad Request**
```json
{
  "status": "error",
  "errorCode": "INVALID_REQUEST",
  "errorMessage": "Invalid request parameters",
  "details": {
    "field": "username",
    "reason": "Invalid email format"
  }
}
```

**409 Conflict**
```json
{
  "status": "error",
  "errorCode": "USER_ALREADY_EXISTS",
  "errorMessage": "User already registered",
  "details": {
    "username": "user@example.com"
  }
}
```

**429 Too Many Requests**
```json
{
  "status": "error",
  "errorCode": "RATE_LIMIT_EXCEEDED",
  "errorMessage": "Too many requests",
  "details": {
    "retryAfter": 60,
    "limit": 10,
    "window": 60
  }
}
```

### 2.2 Registration Verification

#### Endpoint
```
POST /api/v1/registration/verify
```

#### Request Body
```json
{
  "credential": {
    "id": "bmV3LWNyZWRlbnRpYWwtaWQtYmFzZTY0dXJsLWVuY29kZWQ",
    "rawId": "bmV3LWNyZWRlbnRpYWwtaWQtYmFzZTY0dXJsLWVuY29kZWQ",
    "response": {
      "attestationObject": "b2JqZWN0LWF0dGVzdGF0aW9uLWNib3ItZW5jb2RlZA",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoi..."
    },
    "type": "public-key",
    "clientExtensionResults": {
      "credProps": {
        "rk": false
      },
      "largeBlob": {
        "supported": true
      }
    }
  },
  "sessionData": {
    "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "username": "user@example.com",
    "userVerification": "preferred",
    "attestation": "none"
  }
}
```

#### Request Validation
- `credential.id`: Required, base64url-encoded credential ID
- `credential.rawId`: Required, base64url-encoded raw credential ID
- `credential.response.attestationObject`: Required, base64url-encoded CBOR
- `credential.response.clientDataJSON`: Required, base64url-encoded JSON
- `credential.type`: Required, must be "public-key"
- `sessionData.challenge`: Required, must match original challenge
- `sessionData.username`: Required, must match original username

#### Response (200 OK)
```json
{
  "status": "ok",
  "credentialId": "bmV3LWNyZWRlbnRpYWwtaWQtYmFzZTY0dXJsLWVuY29kZWQ",
  "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
  "registrationTime": "2024-01-15T10:30:00Z",
  "aaguid": "YWFndWlkLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
  "signCount": 0,
  "userVerified": true,
  "credentialType": "public-key",
  "attestationType": "none",
  "authenticatorInfo": {
    "aaguid": "YWFndWlkLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "signCount": 0,
    "cloneWarning": false
  },
  "extensions": {
    "credProps": {
      "rk": false,
      "authenticatorDisplayName": "Platform Authenticator"
    },
    "largeBlob": {
      "supported": true
    }
  }
}
```

#### Error Responses

**400 Bad Request**
```json
{
  "status": "error",
  "errorCode": "INVALID_ATTESTATION",
  "errorMessage": "Invalid attestation data",
  "details": {
    "reason": "Invalid attestation format",
    "format": "unsupported"
  }
}
```

**401 Unauthorized**
```json
{
  "status": "error",
  "errorCode": "ATTESTATION_VERIFICATION_FAILED",
  "errorMessage": "Attestation verification failed",
  "details": {
    "reason": "Invalid signature"
  }
}
```

**422 Unprocessable Entity**
```json
{
  "status": "error",
  "errorCode": "INVALID_CLIENT_DATA",
  "errorMessage": "Invalid client data",
  "details": {
    "field": "challenge",
    "reason": "Challenge mismatch"
  }
}
```

## 3. Authentication API

### 3.1 Authentication Challenge

#### Endpoint
```
POST /api/v1/authentication/challenge
```

#### Request Body
```json
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged",
  "extensions": {
    "largeBlob": {
      "read": true
    }
  }
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "challenge": "YXV0aGVudGljYXRpb24tY2hhbGxlbmdlLWJhc2U2NHVybC1lbmNvZGVk",
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "preferred",
  "timeout": 60000,
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    }
  }
}
```

#### Error Responses

**404 Not Found**
```json
{
  "status": "error",
  "errorCode": "USER_NOT_FOUND",
  "errorMessage": "User not found",
  "details": {
    "username": "user@example.com"
  }
}
```

**422 Unprocessable Entity**
```json
{
  "status": "error",
  "errorCode": "NO_CREDENTIALS",
  "errorMessage": "No credentials found for user",
  "details": {
    "username": "user@example.com"
  }
}
```

### 3.2 Authentication Verification

#### Endpoint
```
POST /api/v1/authentication/verify
```

#### Request Body
```json
{
  "credential": {
    "id": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "rawId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "response": {
      "authenticatorData": "YXV0aGVudGljYXRvci1kYXRhLWJhc2U2NHVybC1lbmNvZGVk",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoi...",
      "signature": "c2lnbmF0dXJlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
      "userHandle": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ"
    },
    "type": "public-key",
    "clientExtensionResults": {
      "largeBlob": {
        "blob": "bGFyZ2UtYmxvYi1kYXRhLWJhc2U2NHVybC1lbmNvZGVk",
        "written": true
      }
    }
  },
  "sessionData": {
    "challenge": "YXV0aGVudGljYXRpb24tY2hhbGxlbmdlLWJhc2U2NHVybC1lbmNvZGVk",
    "username": "user@example.com",
    "userVerification": "preferred"
  }
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
  "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
  "authenticationTime": "2024-01-15T11:45:00Z",
  "newSignCount": 42,
  "userVerified": true,
  "credentialType": "public-key",
  "authenticatorInfo": {
    "aaguid": "YWFndWlkLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "signCount": 42,
    "cloneWarning": false
  },
  "extensions": {
    "largeBlob": {
      "blob": "bGFyZ2UtYmxvYi1kYXRhLWJhc2U2NHVybC1lbmNvZGVk",
      "written": true
    }
  }
}
```

#### Error Responses

**401 Unauthorized**
```json
{
  "status": "error",
  "errorCode": "INVALID_ASSERTION",
  "errorMessage": "Invalid assertion signature",
  "details": {
    "reason": "Signature verification failed"
  }
}
```

**404 Not Found**
```json
{
  "status": "error",
  "errorCode": "CREDENTIAL_NOT_FOUND",
  "errorMessage": "Credential not found",
  "details": {
    "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA"
  }
}
```

## 4. Credential Management API

### 4.1 List User Credentials

#### Endpoint
```
GET /api/v1/credentials
```

#### Request Headers
```
Authorization: Bearer <jwt-token>
```

#### Query Parameters
- `username`: Filter by username (optional)
- `limit`: Maximum number of results (default: 50, max: 100)
- `offset`: Pagination offset (default: 0)

#### Response (200 OK)
```json
{
  "status": "ok",
  "credentials": [
    {
      "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
      "username": "user@example.com",
      "displayName": "John Doe",
      "credentialType": "public-key",
      "attestationType": "none",
      "aaguid": "YWFndWlkLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
      "signCount": 42,
      "backupEligible": false,
      "backupState": false,
      "transports": ["internal"],
      "createdAt": "2024-01-15T10:30:00Z",
      "lastUsed": "2024-01-15T11:45:00Z",
      "userVerified": true,
      "extensions": {
        "credProps": {
          "rk": false
        }
      }
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 50,
    "offset": 0,
    "hasMore": false
  }
}
```

### 4.2 Delete Credential

#### Endpoint
```
DELETE /api/v1/credentials/{credentialId}
```

#### Path Parameters
- `credentialId`: Base64url-encoded credential ID

#### Response (200 OK)
```json
{
  "status": "ok",
  "message": "Credential deleted successfully",
  "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA"
}
```

#### Error Responses

**404 Not Found**
```json
{
  "status": "error",
  "errorCode": "CREDENTIAL_NOT_FOUND",
  "errorMessage": "Credential not found",
  "details": {
    "credentialId": "Y3JlZGVudGlhbC1pZC1iYXNlNjR1cmwtZW5jb2RlZA"
  }
}
```

## 5. User Management API

### 5.1 Create User

#### Endpoint
```
POST /api/v1/users
```

#### Request Body
```json
{
  "username": "newuser@example.com",
  "displayName": "New User",
  "metadata": {
    "department": "Engineering",
    "role": "Developer"
  }
}
```

#### Response (201 Created)
```json
{
  "status": "ok",
  "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
  "username": "newuser@example.com",
  "displayName": "New User",
  "createdAt": "2024-01-15T12:00:00Z",
  "isActive": true
}
```

### 5.2 Get User

#### Endpoint
```
GET /api/v1/users/{userId}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
  "username": "user@example.com",
  "displayName": "John Doe",
  "createdAt": "2024-01-15T10:30:00Z",
  "lastLogin": "2024-01-15T11:45:00Z",
  "isActive": true,
  "credentialCount": 2,
  "metadata": {
    "department": "Engineering",
    "role": "Developer"
  }
}
```

### 5.3 Update User

#### Endpoint
```
PUT /api/v1/users/{userId}
```

#### Request Body
```json
{
  "displayName": "Updated Name",
  "isActive": true,
  "metadata": {
    "department": "Product",
    "role": "Manager"
  }
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ",
  "username": "user@example.com",
  "displayName": "Updated Name",
  "updatedAt": "2024-01-15T12:30:00Z",
  "isActive": true
}
```

### 5.4 Delete User

#### Endpoint
```
DELETE /api/v1/users/{userId}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "message": "User deleted successfully",
  "userId": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ"
}
```

## 6. Health and Status API

### 6.1 Health Check

#### Endpoint
```
GET /api/v1/health
```

#### Response (200 OK)
```json
{
  "status": "healthy",
  "timestamp": "2024-01-15T12:00:00Z",
  "version": "1.0.0",
  "uptime": 3600,
  "checks": {
    "database": {
      "status": "healthy",
      "responseTime": 5
    },
    "memory": {
      "status": "healthy",
      "usage": "45%"
    },
    "disk": {
      "status": "healthy",
      "usage": "23%"
    }
  }
}
```

### 6.2 Server Info

#### Endpoint
```
GET /api/v1/info
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "server": {
    "name": "FIDO2/WebAuthn Server",
    "version": "1.0.0",
    "build": "2024-01-15T10:00:00Z",
    "environment": "production"
  },
  "webauthn": {
    "version": "FIDO2/WebAuthn Level 2",
    "supportedAlgorithms": [
      { "alg": -7, "type": "ES256" },
      { "alg": -257, "type": "RS256" },
      { "alg": -37, "type": "ES384" },
      { "alg": -8, "type": "EdDSA" }
    ],
    "supportedAttestationFormats": [
      "packed",
      "fido-u2f",
      "none"
    ],
    "supportedExtensions": [
      "credProps",
      "largeBlob"
    ]
  },
  "security": {
    "tlsVersion": "1.3",
    "cipherSuites": ["TLS_AES_256_GCM_SHA384"],
    "rateLimiting": {
      "registration": "10/minute",
      "authentication": "30/minute"
    }
  }
}
```

## 7. Error Handling

### 7.1 Standard Error Format

All error responses follow this format:
```json
{
  "status": "error",
  "errorCode": "ERROR_CODE",
  "errorMessage": "Human-readable error message",
  "details": {
    "field": "optional field name",
    "reason": "detailed reason",
    "additional": "context-specific data"
  },
  "timestamp": "2024-01-15T12:00:00Z",
  "requestId": "req-123456789"
}
```

### 7.2 Error Codes

#### Client Errors (4xx)
- `INVALID_REQUEST` (400): Malformed request
- `INVALID_CREDENTIAL_DATA` (400): Invalid credential format
- `INVALID_CLIENT_DATA` (400): Invalid client data JSON
- `MISSING_REQUIRED_FIELD` (400): Required field missing
- `UNAUTHORIZED` (401): Authentication failed
- `FORBIDDEN` (403): Access denied
- `USER_NOT_FOUND` (404): User does not exist
- `CREDENTIAL_NOT_FOUND` (404): Credential does not exist
- `USER_ALREADY_EXISTS` (409): User already registered
- `CREDENTIAL_ALREADY_EXISTS` (409): Credential already registered
- `RATE_LIMIT_EXCEEDED` (429): Too many requests

#### Server Errors (5xx)
- `INTERNAL_SERVER_ERROR` (500): Unexpected server error
- `DATABASE_ERROR` (500): Database operation failed
- `CRYPTOGRAPHIC_ERROR` (500): Cryptographic operation failed
- `SERVICE_UNAVAILABLE` (503): Service temporarily unavailable

#### WebAuthn Specific Errors
- `INVALID_ATTESTATION` (400): Attestation verification failed
- `INVALID_ASSERTION` (401): Assertion verification failed
- `CHALLENGE_EXPIRED` (400): Challenge has expired
- `CHALLENGE_ALREADY_USED` (400): Challenge already used
- `COUNTER_REGRESSION` (400): Authentication counter regression
- `RP_ID_MISMATCH` (400): RP ID does not match
- `ORIGIN_MISMATCH` (400): Origin does not match
- `UNSUPPORTED_ALGORITHM` (400): Unsupported cryptographic algorithm
- `UNSUPPORTED_FORMAT` (400): Unsupported attestation format

## 8. Security Headers

All responses include these security headers:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

## 9. API Versioning

### 9.1 Version Strategy
- URL path versioning: `/api/v1/`, `/api/v2/`
- Backward compatibility maintained for at least one previous version
- Deprecation notices sent 6 months before removal

### 9.2 Version Negotiation
- Default to latest stable version
- Client can specify version via URL
- Version information available in `/api/info` endpoint

## 10. Testing Endpoints

### 10.1 Conformance Test Support

#### Test Setup Endpoint
```
POST /api/v1/test/setup
```

#### Test Cleanup Endpoint
```
POST /api/v1/test/cleanup
```

#### Test Data Injection
```
POST /api/v1/test/inject
```

These endpoints are only available in test environments and support FIDO Alliance conformance testing requirements.

This API specification provides a comprehensive foundation for implementing a FIDO2/WebAuthn server that meets both functional requirements and FIDO Alliance compliance standards.