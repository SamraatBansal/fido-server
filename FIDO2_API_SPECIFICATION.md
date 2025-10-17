# FIDO2/WebAuthn API Specification

## Overview

This document provides a detailed API specification for the FIDO2/WebAuthn Relying Party Server, aligned with the FIDO Alliance Conformance Test API specification. The API implements REST endpoints for registration and authentication flows with comprehensive error handling and security features.

## 1. API Architecture

### 1.1 Base Configuration

- **Base URL**: `https://rp.example.com/api/v1`
- **Protocol**: HTTPS only (TLS 1.2+)
- **Content-Type**: `application/json`
- **Character Encoding**: UTF-8
- **API Version**: v1

### 1.2 Authentication

- **Method**: Bearer Token (optional for public endpoints)
- **Rate Limiting**: 100 requests per minute per IP
- **CORS**: Configured for allowed origins
- **CSRF Protection**: Enabled for state-changing operations

### 1.3 Response Format

All responses follow a consistent structure:

```json
{
  "status": "ok|error",
  "data": { /* Response data */ } | null,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": { /* Additional error details */ }
  } | null,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 2. Registration API

### 2.1 Registration Challenge Endpoint

#### 2.1.1 Request

**Endpoint**: `POST /api/v1/registration/challenge`

**Headers**:
```
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

**Request Body**:
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise|indirect",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged",
    "residentKey": "required|preferred|discouraged"
  },
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "required"
    },
    "minPinLength": true,
    "hmacCreateSecret": true
  },
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ]
}
```

**Request Validation**:
- `username`: Required, valid email format, 1-255 characters
- `displayName`: Required, 1-255 characters
- `userVerification`: Optional, enum validation
- `attestation`: Optional, enum validation
- `authenticatorSelection`: Optional, object validation
- `extensions`: Optional, extension-specific validation
- `excludeCredentials`: Optional, array of credential descriptors

#### 2.1.2 Success Response (200 OK)

```json
{
  "status": "ok",
  "data": {
    "challenge": "base64url-challenge-string",
    "rp": {
      "id": "example.com",
      "name": "Example Service"
    },
    "user": {
      "id": "base64url-user-id",
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
      }
    ],
    "timeout": 60000,
    "excludeCredentials": [
      {
        "type": "public-key",
        "id": "base64url-credential-id",
        "transports": ["internal", "usb", "nfc", "ble"]
      }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "requireResidentKey": false,
      "userVerification": "required",
      "residentKey": "preferred"
    },
    "attestation": "direct",
    "extensions": {
      "credProps": true,
      "largeBlob": {
        "support": "required"
      },
      "minPinLength": true,
      "hmacCreateSecret": true
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 2.1.3 Error Responses

**400 Bad Request - Invalid Input**:
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request parameters",
    "details": {
      "field": "username",
      "reason": "Invalid email format"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**429 Too Many Requests**:
```json
{
  "status": "error",
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Too many requests",
    "details": {
      "retryAfter": 60,
      "limit": 100,
      "window": 60
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**500 Internal Server Error**:
```json
{
  "status": "error",
  "error": {
    "code": "INTERNAL_ERROR",
    "message": "Internal server error",
    "details": {
      "requestId": "req_123456789"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 2.2 Registration Verification Endpoint

#### 2.2.1 Request

**Endpoint**: `POST /api/v1/registration/verify`

**Headers**:
```
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

**Request Body**:
```json
{
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64url-raw-credential-id",
    "response": {
      "attestationObject": "base64url-attestation-object",
      "clientDataJSON": "base64url-client-data-json",
      "transports": ["internal", "usb", "nfc", "ble"]
    },
    "type": "public-key",
    "clientExtensionResults": {
      "credProps": {
        "rk": true
      },
      "largeBlob": {
        "supported": true
      }
    }
  },
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required",
  "attestation": "direct"
}
```

**Request Validation**:
- `credential`: Required, valid PublicKeyCredential structure
- `credential.id`: Required, base64url string, 1-1024 characters
- `credential.rawId`: Required, base64url string
- `credential.response`: Required, valid AuthenticatorAttestationResponse
- `credential.type`: Required, must be "public-key"
- `username`: Required, must match challenge request
- `displayName`: Optional, user display name
- `userVerification`: Optional, must match challenge request
- `attestation`: Optional, must match challenge request

#### 2.2.2 Success Response (200 OK)

```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-credential-id",
    "credentialType": "public-key",
    "aaguid": "base64url-aaguid",
    "signCount": 0,
    "userVerified": true,
    "attestationType": "packed",
    "attestationTrustPath": [
      "base64url-certificate-1",
      "base64url-certificate-2"
    ],
    "authenticatorInfo": {
      "aaguid": "base64url-aaguid",
      "signCount": 0,
      "cloneWarning": false
    },
    "clientExtensionResults": {
      "credProps": {
        "rk": true
      },
      "largeBlob": {
        "supported": true
      }
    },
    "transports": ["internal", "usb", "nfc", "ble"],
    "registrationInfo": {
      "registeredAt": "2024-01-01T00:00:00Z",
      "userId": "base64url-user-id",
      "username": "user@example.com"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 2.2.3 Error Responses

**400 Bad Request - Invalid Attestation**:
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_ATTESTATION",
    "message": "Attestation verification failed",
    "details": {
      "reason": "Invalid signature",
      "credentialId": "base64url-credential-id"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**400 Bad Request - Invalid Challenge**:
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_CHALLENGE",
    "message": "Invalid or expired challenge",
    "details": {
      "challengeId": "challenge-123",
      "reason": "expired"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**409 Conflict - Duplicate Credential**:
```json
{
  "status": "error",
  "error": {
    "code": "DUPLICATE_CREDENTIAL",
    "message": "Credential already registered",
    "details": {
      "credentialId": "base64url-credential-id",
      "existingUserId": "base64url-existing-user-id"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 3. Authentication API

### 3.1 Authentication Challenge Endpoint

#### 3.1.1 Request

**Endpoint**: `POST /api/v1/authentication/challenge`

**Headers**:
```
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

**Request Body**:
```json
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged",
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    },
    "credProps": true
  },
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ]
}
```

**Request Validation**:
- `username`: Required, valid email format
- `userVerification`: Optional, enum validation
- `extensions`: Optional, extension-specific validation
- `allowCredentials`: Optional, array of credential descriptors

#### 3.1.2 Success Response (200 OK)

```json
{
  "status": "ok",
  "data": {
    "challenge": "base64url-challenge-string",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "base64url-credential-id",
        "transports": ["internal", "usb", "nfc", "ble"]
      }
    ],
    "userVerification": "required",
    "rpId": "example.com",
    "timeout": 60000,
    "extensions": {
      "largeBlob": {
        "read": true,
        "write": true
      },
      "credProps": true
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 3.1.3 Error Responses

**404 Not Found - User Not Found**:
```json
{
  "status": "error",
  "error": {
    "code": "USER_NOT_FOUND",
    "message": "User not found",
    "details": {
      "username": "user@example.com"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**400 Bad Request - No Credentials**:
```json
{
  "status": "error",
  "error": {
    "code": "NO_CREDENTIALS",
    "message": "No credentials found for user",
    "details": {
      "username": "user@example.com"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 3.2 Authentication Verification Endpoint

#### 3.2.1 Request

**Endpoint**: `POST /api/v1/authentication/verify`

**Headers**:
```
Content-Type: application/json
X-Requested-With: XMLHttpRequest
```

**Request Body**:
```json
{
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64url-raw-credential-id",
    "response": {
      "authenticatorData": "base64url-authenticator-data",
      "clientDataJSON": "base64url-client-data-json",
      "signature": "base64url-signature",
      "userHandle": "base64url-user-handle"
    },
    "type": "public-key",
    "clientExtensionResults": {
      "largeBlob": {
        "blob": "base64url-blob-data",
        "written": true
      }
    }
  },
  "userVerification": "required"
}
```

**Request Validation**:
- `credential`: Required, valid PublicKeyCredential structure
- `credential.id`: Required, base64url string
- `credential.rawId`: Required, base64url string
- `credential.response`: Required, valid AuthenticatorAssertionResponse
- `credential.type`: Required, must be "public-key"
- `userVerification`: Optional, must match challenge request

#### 3.2.2 Success Response (200 OK)

```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-credential-id",
    "credentialType": "public-key",
    "userVerified": true,
    "newSignCount": 42,
    "authenticatorInfo": {
      "aaguid": "base64url-aaguid",
      "signCount": 42,
      "cloneWarning": false
    },
    "clientExtensionResults": {
      "largeBlob": {
        "blob": "base64url-blob-data",
        "written": true
      }
    },
    "userInfo": {
      "userId": "base64url-user-id",
      "username": "user@example.com",
      "displayName": "John Doe"
    },
    "authenticationInfo": {
      "authenticatedAt": "2024-01-01T00:00:00Z",
      "ipAddress": "192.168.1.1",
      "userAgent": "Mozilla/5.0..."
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 3.2.3 Error Responses

**400 Bad Request - Invalid Assertion**:
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_ASSERTION",
    "message": "Assertion verification failed",
    "details": {
      "reason": "Invalid signature",
      "credentialId": "base64url-credential-id"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**400 Bad Request - Counter Regression**:
```json
{
  "status": "error",
  "error": {
    "code": "COUNTER_REGRESSION",
    "message": "Authentication counter regression detected",
    "details": {
      "credentialId": "base64url-credential-id",
      "oldCounter": 42,
      "newCounter": 40
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

**401 Unauthorized - Invalid Credential**:
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_CREDENTIAL",
    "message": "Invalid or unknown credential",
    "details": {
      "credentialId": "base64url-credential-id"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 4. Management API

### 4.1 Credential Management

#### 4.1.1 List User Credentials

**Endpoint**: `GET /api/v1/users/{userId}/credentials`

**Headers**:
```
Authorization: Bearer {token}
Content-Type: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "data": {
    "credentials": [
      {
        "credentialId": "base64url-credential-id",
        "type": "public-key",
        "name": "My Security Key",
        "createdAt": "2024-01-01T00:00:00Z",
        "lastUsedAt": "2024-01-01T12:00:00Z",
        "signCount": 42,
        "transports": ["internal", "usb"],
        "backupEligible": true,
        "backupState": true,
        "userVerification": "required"
      }
    ],
    "total": 1
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 4.1.2 Delete Credential

**Endpoint**: `DELETE /api/v1/credentials/{credentialId}`

**Headers**:
```
Authorization: Bearer {token}
Content-Type: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "data": {
    "credentialId": "base64url-credential-id",
    "deletedAt": "2024-01-01T00:00:00Z"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 4.2 User Management

#### 4.2.1 Get User Info

**Endpoint**: `GET /api/v1/users/{userId}`

**Headers**:
```
Authorization: Bearer {token}
Content-Type: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "data": {
    "userId": "base64url-user-id",
    "username": "user@example.com",
    "displayName": "John Doe",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "credentialCount": 2,
    "lastAuthenticationAt": "2024-01-01T12:00:00Z"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### 4.2.2 Delete User

**Endpoint**: `DELETE /api/v1/users/{userId}`

**Headers**:
```
Authorization: Bearer {token}
Content-Type: application/json
```

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "data": {
    "userId": "base64url-user-id",
    "deletedAt": "2024-01-01T00:00:00Z",
    "credentialsDeleted": 2
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 5. Health and Status API

### 5.1 Health Check

**Endpoint**: `GET /api/v1/health`

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "data": {
    "status": "healthy",
    "timestamp": "2024-01-01T00:00:00Z",
    "version": "1.0.0",
    "uptime": 3600,
    "checks": {
      "database": "ok",
      "webauthn": "ok",
      "memory": "ok",
      "disk": "ok"
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 5.2 Service Status

**Endpoint**: `GET /api/v1/status`

**Success Response (200 OK)**:
```json
{
  "status": "ok",
  "data": {
    "service": "FIDO2 WebAuthn Server",
    "version": "1.0.0",
    "environment": "production",
    "uptime": 3600,
    "statistics": {
      "totalUsers": 1000,
      "totalCredentials": 2500,
      "registrationsToday": 50,
      "authenticationsToday": 500
    },
    "configuration": {
      "supportedAlgorithms": ["ES256", "RS256"],
      "supportedAttestations": ["none", "packed", "fido-u2f"],
      "maxCredentialsPerUser": 10,
      "challengeTimeout": 300
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 6. Error Code Reference

### 6.1 Client Errors (4xx)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_REQUEST` | 400 | Invalid request parameters |
| `INVALID_ATTESTATION` | 400 | Attestation verification failed |
| `INVALID_ASSERTION` | 400 | Assertion verification failed |
| `INVALID_CHALLENGE` | 400 | Invalid or expired challenge |
| `INVALID_CREDENTIAL` | 401 | Invalid or unknown credential |
| `USER_NOT_FOUND` | 404 | User not found |
| `NO_CREDENTIALS` | 400 | No credentials found for user |
| `DUPLICATE_CREDENTIAL` | 409 | Credential already registered |
| `COUNTER_REGRESSION` | 400 | Authentication counter regression |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `UNSUPPORTED_ALGORITHM` | 400 | Unsupported cryptographic algorithm |
| `UNSUPPORTED_ATTESTATION` | 400 | Unsupported attestation format |

### 6.2 Server Errors (5xx)

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INTERNAL_ERROR` | 500 | Internal server error |
| `DATABASE_ERROR` | 500 | Database operation failed |
| `CRYPTOGRAPHIC_ERROR` | 500 | Cryptographic operation failed |
| `CONFIGURATION_ERROR` | 500 | Server configuration error |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable |

## 7. Security Headers

All API responses include the following security headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## 8. Rate Limiting

### 8.1 Rate Limit Rules

| Endpoint | Limit | Window |
|----------|-------|--------|
| Registration Challenge | 10/min | 60 seconds |
| Registration Verify | 10/min | 60 seconds |
| Authentication Challenge | 100/min | 60 seconds |
| Authentication Verify | 100/min | 60 seconds |
| Management APIs | 60/min | 60 seconds |

### 8.2 Rate Limit Headers

Rate limited responses include:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
Retry-After: 60
```

## 9. Webhook Support

### 9.1 Registration Webhook

**Endpoint**: Configurable webhook URL

**Payload**:
```json
{
  "event": "credential.registered",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    "userId": "base64url-user-id",
    "username": "user@example.com",
    "credentialId": "base64url-credential-id",
    "aaguid": "base64url-aaguid",
    "attestationType": "packed"
  }
}
```

### 9.2 Authentication Webhook

**Endpoint**: Configurable webhook URL

**Payload**:
```json
{
  "event": "credential.authenticated",
  "timestamp": "2024-01-01T00:00:00Z",
  "data": {
    "userId": "base64url-user-id",
    "username": "user@example.com",
    "credentialId": "base64url-credential-id",
    "signCount": 42,
    "userVerified": true,
    "ipAddress": "192.168.1.1"
  }
}
```

## 10. FIDO2 Conformance Test Support

### 10.1 Test Mode Configuration

The API supports a special test mode for FIDO2 conformance testing:

**Header**: `X-FIDO2-Test-Mode: true`

**Test Mode Features**:
- Bypass rate limiting
- Use deterministic challenges
- Skip some security validations
- Provide detailed error information

### 10.2 Conformance Test Endpoints

#### 10.2.1 Test Configuration

**Endpoint**: `POST /api/v1/test/configure`

**Request Body**:
```json
{
  "rpId": "test.example.com",
  "origin": "https://test.example.com",
  "testMode": true,
  "deterministicChallenges": true,
  "skipAttestationVerification": false
}
```

#### 10.2.2 Test Status

**Endpoint**: `GET /api/v1/test/status`

**Response**:
```json
{
  "status": "ok",
  "data": {
    "testMode": true,
    "rpId": "test.example.com",
    "origin": "https://test.example.com",
    "testCases": {
      "registration": {
        "total": 50,
        "passed": 48,
        "failed": 2
      },
      "authentication": {
        "total": 45,
        "passed": 45,
        "failed": 0
      }
    }
  }
}
```

This API specification provides a comprehensive foundation for implementing a FIDO2/WebAuthn Relying Party Server that is fully compliant with FIDO Alliance specifications and ready for conformance testing.