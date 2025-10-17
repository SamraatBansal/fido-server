# FIDO2/WebAuthn Server - API Specification

## Overview

This document provides a detailed API specification for the FIDO2/WebAuthn Relying Party Server, aligned with FIDO Alliance conformance test requirements. The API follows REST principles and implements all required WebAuthn operations with comprehensive error handling and security features.

## 1. API Architecture

### 1.1 Base Configuration
- **Base URL**: `https://your-domain.com/api/v1`
- **Protocol**: HTTPS only (TLS 1.2+)
- **Content-Type**: `application/json`
- **Character Encoding**: UTF-8
- **API Version**: v1

### 1.2 Authentication
- API endpoints use WebAuthn-based authentication
- Session management via secure HTTP-only cookies
- CSRF protection for state-changing operations
- Rate limiting: 100 requests/minute per IP address

### 1.3 Response Format
All responses follow a consistent structure:

```json
{
  "status": "ok|error",
  "data": { ... },  // Present on success
  "error": {        // Present on error
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": "Additional error details"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 2. Registration API

### 2.1 Registration Challenge

**Endpoint**: `POST /webauthn/register/challenge`

Initiates the registration ceremony by generating a cryptographic challenge.

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
    "largeBlob": {
      "support": "required"
    }
  }
}
```

#### Request Validation
- `username`: Required, 3-255 characters, valid email format
- `displayName`: Required, 1-255 characters, no control characters
- `userVerification`: Optional, defaults to "preferred"
- `attestation`: Optional, defaults to "none"
- `authenticatorSelection`: Optional, object with authenticator preferences
- `extensions`: Optional, WebAuthn extensions

#### Response
```json
{
  "status": "ok",
  "data": {
    "challenge": "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA",
    "rp": {
      "id": "example.com",
      "name": "FIDO Server"
    },
    "user": {
      "id": "dXNlcl9pZF8xMjM0NTY3ODkw",
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
    "timeout": 300000,
    "attestation": "none",
    "authenticatorSelection": {
      "authenticatorAttachment": "cross-platform",
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "extensions": {
      "credProps": true
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Response Fields
- `challenge`: Base64URL-encoded random challenge (minimum 16 bytes)
- `rp`: Relying Party information
- `user`: User information with Base64URL-encoded ID
- `pubKeyCredParams`: Supported public key algorithms
- `timeout`: Ceremony timeout in milliseconds (default: 300000)
- `attestation`: Attestation conveyance preference
- `authenticatorSelection`: Authenticator selection criteria
- `extensions`: Requested extensions

#### Error Responses
```json
{
  "status": "error",
  "error": {
    "code": "INVALID_REQUEST",
    "message": "Invalid request parameters",
    "details": "Username must be a valid email address"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Error Codes
- `INVALID_REQUEST`: Malformed request or invalid parameters
- `RATE_LIMITED`: Too many requests from this IP
- `USER_EXISTS`: User already registered
- `INTERNAL_ERROR`: Server internal error

### 2.2 Registration Verification

**Endpoint**: `POST /webauthn/register/verify`

Verifies the attestation object and completes the registration ceremony.

#### Request
```json
{
  "credential": {
    "id": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
    "rawId": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
    "response": {
      "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGl_Z_6yIw2r5wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8pQECAyYgASFYIEJg7mJ2wL5a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8IlggJg7mJ2wL5a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWUMyY2hhbGxlbmdlXzEyMzQ1Njc4OTAiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
    },
    "type": "public-key"
  },
  "clientExtensionResults": {
    "credProps": {
      "rk": true
    }
  }
}
```

#### Request Validation
- `credential.id`: Required, Base64URL-encoded credential ID
- `credential.rawId`: Required, Base64URL-encoded raw credential ID
- `credential.response.attestationObject`: Required, Base64URL-encoded attestation object
- `credential.response.clientDataJSON`: Required, Base64URL-encoded client data JSON
- `credential.type`: Required, must be "public-key"
- `clientExtensionResults`: Optional, extension results

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentialId": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
    "counter": 0,
    "aaguid": "ADCE0002-35BC-C60A-648B-0B25F1F05503",
    "attestationType": "none",
    "userVerified": true,
    "backupEligible": false,
    "backupState": false,
    "transports": ["internal", "usb", "nfc", "ble"],
    "extensions": {
      "credProps": {
        "rk": true
      }
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Response Fields
- `credentialId`: Base64URL-encoded credential ID
- `counter`: Authenticator counter value
- `aaguid`: Authenticator Attestation GUID
- `attestationType`: Type of attestation (none, basic, self, etc.)
- `userVerified`: Whether user verification was performed
- `backupEligible`: Whether credential is backup eligible
- `backupState`: Current backup state
- `transports`: Supported transport modes
- `extensions`: Extension results

#### Error Codes
- `INVALID_ATTESTATION`: Attestation verification failed
- `INVALID_CHALLENGE`: Challenge is invalid or expired
- `INVALID_RP_ID`: RP ID mismatch
- `INVALID_USER`: User verification failed
- `CREDENTIAL_EXISTS`: Credential ID already exists
- `UNSUPPORTED_ALGORITHM`: Unsupported public key algorithm

## 3. Authentication API

### 3.1 Authentication Challenge

**Endpoint**: `POST /webauthn/authenticate/challenge`

Initiates the authentication ceremony by generating a challenge for existing credentials.

#### Request
```json
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "extensions": {
    "largeBlob": {
      "read": true
    }
  }
}
```

#### Request Validation
- `username`: Required, existing user identifier
- `userVerification`: Optional, defaults to "preferred"
- `allowCredentials`: Optional, list of allowed credential IDs
- `extensions`: Optional, WebAuthn extensions

#### Response
```json
{
  "status": "ok",
  "data": {
    "challenge": "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
        "transports": ["internal", "usb", "nfc", "ble"]
      }
    ],
    "userVerification": "preferred",
    "timeout": 300000,
    "rpId": "example.com",
    "extensions": {
      "largeBlob": {
        "read": true
      }
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Response Fields
- `challenge`: Base64URL-encoded random challenge
- `allowCredentials`: List of allowed credentials for this user
- `userVerification`: User verification requirement
- `timeout`: Ceremony timeout in milliseconds
- `rpId`: Relying Party ID
- `extensions`: Requested extensions

#### Error Codes
- `USER_NOT_FOUND`: User does not exist
- `NO_CREDENTIALS`: User has no registered credentials
- `INVALID_REQUEST`: Malformed request
- `RATE_LIMITED`: Too many requests

### 3.2 Authentication Verification

**Endpoint**: `POST /webauthn/authenticate/verify`

Verifies the assertion object and completes the authentication ceremony.

#### Request
```json
{
  "credential": {
    "id": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
    "rawId": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
    "response": {
      "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiWUMyY2hhbGxlbmdlXzEyMzQ1Njc4OTAiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
      "signature": "MEUCIQCdwBC_9q8f7wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8IgL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8r_9q8f7wL9a9qf3hC5_8",
      "userHandle": "dXNlcl9pZF8xMjM0NTY3ODkw"
    },
    "type": "public-key"
  },
  "clientExtensionResults": {
    "largeBlob": {
      "read": true
    }
  }
}
```

#### Request Validation
- `credential.id`: Required, Base64URL-encoded credential ID
- `credential.rawId`: Required, Base64URL-encoded raw credential ID
- `credential.response.authenticatorData`: Required, Base64URL-encoded authenticator data
- `credential.response.clientDataJSON`: Required, Base64URL-encoded client data JSON
- `credential.response.signature`: Required, Base64URL-encoded signature
- `credential.response.userHandle`: Optional, Base64URL-encoded user handle
- `credential.type`: Required, must be "public-key"
- `clientExtensionResults`: Optional, extension results

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentialId": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
    "counter": 42,
    "userVerified": true,
    "backupEligible": false,
    "backupState": false,
    "extensions": {
      "largeBlob": {
        "read": true
      }
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

#### Response Fields
- `credentialId`: Base64URL-encoded credential ID
- `counter`: Updated authenticator counter value
- `userVerified`: Whether user verification was performed
- `backupEligible`: Whether credential is backup eligible
- `backupState`: Current backup state
- `extensions`: Extension results

#### Error Codes
- `INVALID_ASSERTION`: Assertion verification failed
- `INVALID_CHALLENGE`: Challenge is invalid or expired
- `INVALID_CREDENTIAL`: Credential not found or invalid
- `REPLAY_ATTACK`: Potential replay attack detected
- `COUNTER_MISMATCH`: Authenticator counter validation failed
- `USER_VERIFICATION_FAILED`: User verification required but not provided

## 4. User Management API

### 4.1 Create User

**Endpoint**: `POST /users`

Creates a new user account.

#### Request
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "metadata": {
    "department": "Engineering",
    "role": "Developer"
  }
}
```

#### Response
```json
{
  "status": "ok",
  "data": {
    "id": "dXNlcl9pZF8xMjM0NTY3ODkw",
    "username": "user@example.com",
    "displayName": "John Doe",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 4.2 Get User

**Endpoint**: `GET /users/{userId}`

Retrieves user information.

#### Response
```json
{
  "status": "ok",
  "data": {
    "id": "dXNlcl9pZF8xMjM0NTY3ODkw",
    "username": "user@example.com",
    "displayName": "John Doe",
    "createdAt": "2024-01-01T00:00:00Z",
    "updatedAt": "2024-01-01T00:00:00Z",
    "credentialCount": 2,
    "lastAuthentication": "2024-01-01T12:00:00Z"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 4.3 List User Credentials

**Endpoint**: `GET /users/{userId}/credentials`

Lists all credentials registered to a user.

#### Response
```json
{
  "status": "ok",
  "data": {
    "credentials": [
      {
        "id": "Y3JlZGVudGlhbF9pZF8xMjM0NTY3ODkw",
        "type": "public-key",
        "name": "Security Key",
        "createdAt": "2024-01-01T00:00:00Z",
        "lastUsedAt": "2024-01-01T12:00:00Z",
        "transports": ["usb", "nfc"],
        "backupEligible": false,
        "backupState": false
      }
    ],
    "total": 1
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 4.4 Delete Credential

**Endpoint**: `DELETE /users/{userId}/credentials/{credentialId}`

Deletes a specific credential.

#### Response
```json
{
  "status": "ok",
  "data": {
    "message": "Credential deleted successfully"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 5. Administrative API

### 5.1 Health Check

**Endpoint**: `GET /health`

Returns server health status.

#### Response
```json
{
  "status": "ok",
  "data": {
    "status": "healthy",
    "version": "1.0.0",
    "uptime": 3600,
    "database": "connected",
    "timestamp": "2024-01-01T00:00:00Z"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 5.2 Metrics

**Endpoint**: `GET /metrics`

Returns server metrics (requires admin authentication).

#### Response
```json
{
  "status": "ok",
  "data": {
    "registrations": {
      "total": 1000,
      "today": 25,
      "success_rate": 0.98
    },
    "authentications": {
      "total": 5000,
      "today": 150,
      "success_rate": 0.97
    },
    "users": {
      "total": 800,
      "active_today": 50
    },
    "credentials": {
      "total": 1200,
      "average_per_user": 1.5
    }
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 6. FIDO2 Conformance Test API

### 6.1 Conformance Test Configuration

**Endpoint**: `POST /conformance/configure`

Configures the server for FIDO2 conformance testing.

#### Request
```json
{
  "rpId": "example.com",
  "rpName": "FIDO Conformance Test Server",
  "attestation": "direct",
  "userVerification": "required",
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "required"
    }
  }
}
```

### 6.2 Conformance Test Status

**Endpoint**: `GET /conformance/status`

Returns conformance test configuration status.

#### Response
```json
{
  "status": "ok",
  "data": {
    "configured": true,
    "rpId": "example.com",
    "supportedAlgorithms": [-7, -257, -8],
    "supportedExtensions": ["credProps", "largeBlob"],
    "testMode": true
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 7. Error Handling

### 7.1 Standard Error Response Format

```json
{
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable error message",
    "details": "Additional technical details",
    "requestId": "req_1234567890"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### 7.2 HTTP Status Codes

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Access denied
- `404 Not Found`: Resource not found
- `409 Conflict`: Resource conflict (e.g., duplicate)
- `422 Unprocessable Entity`: Valid request but semantic error
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

### 7.3 Error Code Reference

#### Registration Errors
- `REG_001`: Invalid username format
- `REG_002`: User already exists
- `REG_003`: Invalid attestation format
- `REG_004`: Attestation verification failed
- `REG_005`: Challenge expired
- `REG_006`: RP ID mismatch
- `REG_007`: Unsupported algorithm
- `REG_008`: Credential already exists

#### Authentication Errors
- `AUTH_001`: User not found
- `REG_002`: No credentials for user
- `AUTH_003`: Invalid assertion format
- `AUTH_004`: Assertion verification failed
- `AUTH_005`: Challenge expired
- `AUTH_006`: Replay attack detected
- `AUTH_007`: Counter validation failed
- `AUTH_008`: User verification required

#### System Errors
- `SYS_001`: Database connection error
- `SYS_002`: Internal server error
- `SYS_003`: Service unavailable
- `SYS_004`: Rate limit exceeded
- `SYS_005`: Invalid configuration

## 8. Security Headers

All API responses include the following security headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## 9. Rate Limiting

### 9.1 Rate Limit Configuration
- **Global limit**: 1000 requests/minute
- **Per IP limit**: 100 requests/minute
- **Per user limit**: 50 requests/minute
- **Authentication limit**: 10 attempts/minute per user

### 9.2 Rate Limit Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

### 9.3 Rate Limit Response
```json
{
  "status": "error",
  "error": {
    "code": "RATE_LIMITED",
    "message": "Too many requests",
    "details": "Rate limit exceeded. Try again later.",
    "retryAfter": 60
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 10. API Versioning

### 10.1 Version Strategy
- URL path versioning: `/api/v1/`, `/api/v2/`
- Backward compatibility maintained for at least 2 versions
- Deprecation notices sent 6 months before removal

### 10.2 Version Headers
```http
API-Version: 1.0
Supported-Versions: 1.0, 1.1
Deprecated-Versions: 
```

## 11. Testing and Validation

### 11.1 API Testing Endpoints
- `POST /test/reset`: Reset test database (test environment only)
- `GET /test/fixtures`: Load test fixtures
- `POST /test/simulate`: Simulate various scenarios

### 11.2 Validation Tools
- OpenAPI/Swagger specification available at `/api/docs`
- Postman collection for API testing
- Automated API contract tests

This API specification provides a comprehensive foundation for implementing a FIDO2/WebAuthn server that meets FIDO Alliance conformance requirements while maintaining security, performance, and usability standards.