# FIDO2/WebAuthn Server - API Specification

## Overview

This API specification defines the REST endpoints for the FIDO2/WebAuthn Relying Party Server, designed to be compatible with the FIDO Alliance Conformance Test Tools. The API follows the WebAuthn Level 2 specification and implements all required operations for registration and authentication flows.

## Base Configuration

- **Base URL**: `https://rp.example.com`
- **API Version**: v1
- **Content-Type**: `application/json`
- **Character Encoding**: UTF-8
- **TLS Required**: Yes (TLS 1.2+)

## Common Headers

```http
Content-Type: application/json
Accept: application/json
User-Agent: FIDO-Server/1.0
X-Request-ID: <unique-request-identifier>
```

## Common Response Format

### Success Response
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    // Response-specific data
  }
}
```

### Error Response
```json
{
  "status": "error",
  "errorMessage": "Human-readable error description",
  "errorCode": "ERROR_CODE",
  "details": {
    // Additional error details
  }
}
```

## 1. Registration Endpoints

### 1.1 Begin Registration

**Endpoint**: `POST /webauthn/register/begin`

**Description**: Initiates the WebAuthn registration ceremony by generating a challenge and returning credential creation options.

#### Request
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "preferred",
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "preferred",
    "residentKey": "preferred"
  },
  "extensions": {
    "credProps": true,
    "largeBlob": {
      "support": "preferred"
    },
    "minPinLength": true,
    "uvm": true,
    "credProtect": {
      "credentialProtectionPolicy": "userVerificationOptional",
      "enforceCredentialProtectionPolicy": false
    }
  },
  "excludeCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ]
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| username | string | Yes | User identifier (email format recommended) |
| displayName | string | Yes | Human-readable user name |
| userVerification | string | No | "required", "preferred", or "discouraged" |
| attestation | string | No | "none", "indirect", "direct", or "enterprise" |
| authenticatorSelection | object | No | Authenticator selection criteria |
| extensions | object | No | WebAuthn extensions |
| excludeCredentials | array | No | Credentials to exclude from registration |

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "rp": {
      "id": "example.com",
      "name": "FIDO Server Example"
    },
    "user": {
      "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
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
        "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
        "transports": ["usb", "nfc", "ble", "internal"]
      }
    ],
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "requireResidentKey": false,
      "userVerification": "preferred",
      "residentKey": "preferred"
    },
    "attestation": "direct",
    "extensions": {
      "credProps": true,
      "largeBlob": {
        "support": "preferred"
      },
      "minPinLength": true,
      "uvm": true,
      "credProtect": {
        "credentialProtectionPolicy": "userVerificationOptional",
        "enforceCredentialProtectionPolicy": false
      }
    }
  }
}
```

#### Error Responses

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | INVALID_REQUEST | Malformed request or invalid parameters |
| 401 | UNAUTHORIZED | Authentication required |
| 409 | USER_EXISTS | User already registered |
| 422 | VALIDATION_ERROR | Request validation failed |
| 500 | INTERNAL_ERROR | Server internal error |

### 1.2 Finish Registration

**Endpoint**: `POST /webauthn/register/finish`

**Description**: Completes the WebAuthn registration ceremony by validating the attestation response and storing the credential.

#### Request
```json
{
  "credential": {
    "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "rawId": "YmFzZTY0dXJsLWVuY29kZWQtcmF3LWlk",
    "response": {
      "attestationObject": "b2JqZWN0LWF0dGVzdGF0aW9uLWNvZGVk",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiY2hhbGxlbmdlLXZhbHVlIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
      "transports": ["usb", "nfc", "ble", "internal"]
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
  "sessionData": {
    "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "userId": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "userVerification": "preferred",
    "timestamp": "2023-12-01T10:00:00Z"
  }
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| credential | object | Yes | Credential creation response from authenticator |
| sessionData | object | Yes | Session data from registration begin |

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "credentialId": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "user": {
      "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "authenticatorInfo": {
      "aaguid": "AAAAAAAAAAAAAAAAAAAAAA",
      "signCount": 0,
      "cloneWarning": false,
      "attestationType": "basic",
      "attestationTrustPath": [
        "base64-encoded-certificate-1",
        "base64-encoded-certificate-2"
      ]
    },
    "credentialInfo": {
      "type": "public-key",
      "transports": ["usb", "nfc", "ble", "internal"],
      "backupEligible": true,
      "backupState": false,
      "userVerification": "preferred"
    },
    "registrationInfo": {
      "registeredAt": "2023-12-01T10:00:00Z",
      "rpId": "example.com",
      "origin": "https://example.com"
    }
  }
}
```

#### Error Responses

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | INVALID_CREDENTIAL | Invalid credential data |
| 401 | INVALID_CHALLENGE | Challenge validation failed |
| 409 | CREDENTIAL_EXISTS | Credential already registered |
| 422 | ATTESTATION_FAILED | Attestation validation failed |
| 500 | INTERNAL_ERROR | Server internal error |

## 2. Authentication Endpoints

### 2.1 Begin Authentication

**Endpoint**: `POST /webauthn/authenticate/begin`

**Description**: Initiates the WebAuthn authentication ceremony by generating a challenge and returning credential request options.

#### Request
```json
{
  "username": "user@example.com",
  "userVerification": "preferred",
  "extensions": {
    "largeBlob": {
      "read": true,
      "write": true
    },
    "uvm": true,
    "credProps": true
  }
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| username | string | Yes | User identifier |
| userVerification | string | No | "required", "preferred", or "discouraged" |
| extensions | object | No | WebAuthn extensions |

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "rpId": "example.com",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
        "transports": ["usb", "nfc", "ble", "internal"]
      }
    ],
    "userVerification": "preferred",
    "timeout": 60000,
    "extensions": {
      "largeBlob": {
        "read": true,
        "write": true
      },
      "uvm": true,
      "credProps": true
    }
  }
}
```

#### Error Responses

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | INVALID_REQUEST | Malformed request or invalid parameters |
| 404 | USER_NOT_FOUND | User not found |
| 422 | VALIDATION_ERROR | Request validation failed |
| 500 | INTERNAL_ERROR | Server internal error |

### 2.2 Finish Authentication

**Endpoint**: `POST /webauthn/authenticate/finish`

**Description**: Completes the WebAuthn authentication ceremony by validating the assertion response.

#### Request
```json
{
  "credential": {
    "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "rawId": "YmFzZTY0dXJsLWVuY29kZWQtcmF3LWlk",
    "response": {
      "authenticatorData": "YXV0aGVudGljYXRvci1kYXRhLWJhc2U2NHVybA",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY2hhbGxlbmdlLXZhbHVlIiwib3JpZ2luIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
      "signature": "c2lnbmF0dXJlLWJhc2U2NHVybC1lbmNvZGVk",
      "userHandle": "dXNlci1oYW5kbGUtYmFzZTY0dXJsLWVuY29kZWQ"
    },
    "type": "public-key",
    "clientExtensionResults": {
      "largeBlob": {
        "blob": "base64-encoded-large-blob-data",
        "written": true
      },
      "uvm": [
        {
          "userVerificationMethod": 1,
          "keyProtectionType": 1,
          "matcherProtectionType": 2,
          "authenticatorAttachment": 1
        }
      ]
    }
  },
  "sessionData": {
    "challenge": "Y2hhbGxlbmdlLXZhbHVlLWJhc2U2NHVybC1lbmNvZGVk",
    "username": "user@example.com",
    "userVerification": "preferred",
    "timestamp": "2023-12-01T10:05:00Z"
  }
}
```

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| credential | object | Yes | Credential assertion response from authenticator |
| sessionData | object | Yes | Session data from authentication begin |

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "user": {
      "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "name": "user@example.com",
      "displayName": "John Doe"
    },
    "credentialId": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "newSignCount": 123,
    "authenticationInfo": {
      "userVerified": true,
      "authenticatorInfo": {
        "aaguid": "AAAAAAAAAAAAAAAAAAAAAA",
        "signCount": 123,
        "cloneWarning": false
      },
      "credentialInfo": {
        "type": "public-key",
        "transports": ["usb", "nfc", "ble", "internal"],
        "backupEligible": true,
        "backupState": false
      }
    },
    "sessionInfo": {
      "authenticatedAt": "2023-12-01T10:05:00Z",
      "rpId": "example.com",
      "origin": "https://example.com",
      "ipAddress": "192.168.1.100",
      "userAgent": "Mozilla/5.0..."
    }
  }
}
```

#### Error Responses

| Status Code | Error Code | Description |
|-------------|------------|-------------|
| 400 | INVALID_ASSERTION | Invalid assertion data |
| 401 | INVALID_SIGNATURE | Signature verification failed |
| 403 | CREDENTIAL_DISABLED | Credential is disabled |
| 404 | CREDENTIAL_NOT_FOUND | Credential not found |
| 422 | VALIDATION_FAILED | Assertion validation failed |
| 500 | INTERNAL_ERROR | Server internal error |

## 3. User Management Endpoints

### 3.1 Get User Info

**Endpoint**: `GET /users/{userId}`

**Description**: Retrieves user information and associated credentials.

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "user": {
      "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
      "username": "user@example.com",
      "displayName": "John Doe",
      "createdAt": "2023-12-01T10:00:00Z",
      "lastLogin": "2023-12-01T10:05:00Z",
      "isActive": true,
      "emailVerified": true
    },
    "credentials": [
      {
        "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
        "type": "public-key",
        "name": "Security Key",
        "createdAt": "2023-12-01T10:00:00Z",
        "lastUsed": "2023-12-01T10:05:00Z",
        "transports": ["usb", "nfc"],
        "backupEligible": false,
        "backupState": false,
        "isActive": true
      }
    ]
  }
}
```

### 3.2 Delete User

**Endpoint**: `DELETE /users/{userId}`

**Description**: Deletes a user and all associated credentials.

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "deleted": true,
    "deletedCredentials": 2,
    "deletedAt": "2023-12-01T11:00:00Z"
  }
}
```

### 3.3 List User Credentials

**Endpoint**: `GET /users/{userId}/credentials`

**Description**: Lists all credentials associated with a user.

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "credentials": [
      {
        "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
        "type": "public-key",
        "name": "Security Key",
        "createdAt": "2023-12-01T10:00:00Z",
        "lastUsed": "2023-12-01T10:05:00Z",
        "signCount": 123,
        "transports": ["usb", "nfc"],
        "backupEligible": false,
        "backupState": false,
        "isActive": true,
        "aaguid": "AAAAAAAAAAAAAAAAAAAAAA"
      }
    ],
    "total": 1
  }
}
```

## 4. Credential Management Endpoints

### 4.1 Delete Credential

**Endpoint**: `DELETE /credentials/{credentialId}`

**Description**: Deletes a specific credential.

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "deleted": true,
    "deletedAt": "2023-12-01T11:00:00Z"
  }
}
```

### 4.2 Update Credential

**Endpoint**: `PUT /credentials/{credentialId}`

**Description**: Updates credential metadata.

#### Request
```json
{
  "name": "Updated Security Key Name",
  "isActive": true
}
```

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "name": "Updated Security Key Name",
    "isActive": true,
    "updatedAt": "2023-12-01T11:00:00Z"
  }
}
```

## 5. Admin Endpoints

### 5.1 Health Check

**Endpoint**: `GET /health`

**Description**: Returns server health status.

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "status": "healthy",
    "timestamp": "2023-12-01T10:00:00Z",
    "version": "1.0.0",
    "uptime": "2h30m15s",
    "database": {
      "status": "connected",
      "connections": 5,
      "maxConnections": 100
    },
    "memory": {
      "used": "45MB",
      "available": "1.5GB"
    }
  }
}
```

### 5.2 Server Info

**Endpoint**: `GET /info`

**Description**: Returns server configuration and capabilities.

#### Response (200 OK)
```json
{
  "status": "ok",
  "errorMessage": "",
  "data": {
    "version": "1.0.0",
    "webauthnVersion": "Level 2",
    "supportedAlgorithms": [
      {
        "alg": -7,
        "name": "ES256"
      },
      {
        "alg": -257,
        "name": "RS256"
      },
      {
        "alg": -8,
        "name": "EdDSA"
      }
    ],
    "supportedAttestationFormats": [
      "packed",
      "fido-u2f",
      "none",
      "android-key",
      "android-safetynet"
    ],
    "supportedExtensions": [
      "credProps",
      "largeBlob",
      "minPinLength",
      "uvm",
      "credProtect"
    ],
    "rp": {
      "id": "example.com",
      "name": "FIDO Server Example"
    },
    "features": {
      "userVerification": true,
      "residentKey": true,
      "backupEligible": true,
      "multiAuthenticator": true
    }
  }
}
```

## 6. Error Codes Reference

### 6.1 Client Errors (4xx)

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| INVALID_REQUEST | 400 | Malformed request or invalid parameters |
| UNAUTHORIZED | 401 | Authentication required or failed |
| FORBIDDEN | 403 | Access forbidden |
| NOT_FOUND | 404 | Resource not found |
| CONFLICT | 409 | Resource conflict (duplicate) |
| VALIDATION_ERROR | 422 | Request validation failed |
| TOO_MANY_REQUESTS | 429 | Rate limit exceeded |

### 6.2 Server Errors (5xx)

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| INTERNAL_ERROR | 500 | Internal server error |
| NOT_IMPLEMENTED | 501 | Feature not implemented |
| SERVICE_UNAVAILABLE | 503 | Service temporarily unavailable |
| GATEWAY_TIMEOUT | 504 | Gateway timeout |

### 6.3 WebAuthn Specific Errors

| Error Code | Description |
|------------|-------------|
| INVALID_CREDENTIAL | Invalid credential data format |
| INVALID_CHALLENGE | Challenge validation failed |
| INVALID_SIGNATURE | Signature verification failed |
| INVALID_ATTESTATION | Attestation validation failed |
| INVALID_ASSERTION | Assertion validation failed |
| CREDENTIAL_EXISTS | Credential already registered |
| CREDENTIAL_NOT_FOUND | Credential not found |
| CREDENTIAL_DISABLED | Credential is disabled |
| USER_EXISTS | User already registered |
| USER_NOT_FOUND | User not found |
| UNSUPPORTED_ALGORITHM | Unsupported cryptographic algorithm |
| UNSUPPORTED_FORMAT | Unsupported attestation format |
| CLONE_DETECTED | Credential cloning detected |
| COUNTER_REGRESSION | Authentication counter regression |

## 7. Rate Limiting

### 7.1 Rate Limit Configuration

| Endpoint | Limit | Window |
|----------|-------|--------|
| POST /webauthn/register/begin | 10 requests | 1 minute |
| POST /webauthn/register/finish | 10 requests | 1 minute |
| POST /webauthn/authenticate/begin | 30 requests | 1 minute |
| POST /webauthn/authenticate/finish | 30 requests | 1 minute |
| GET /users/* | 100 requests | 1 minute |
| DELETE /users/* | 10 requests | 1 minute |

### 7.2 Rate Limit Headers

```http
X-RateLimit-Limit: 10
X-RateLimit-Remaining: 9
X-RateLimit-Reset: 1701388800
```

## 8. Security Headers

All responses include the following security headers:

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
Referrer-Policy: strict-origin-when-cross-origin
```

## 9. CORS Configuration

```http
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-ID
Access-Control-Max-Age: 86400
Access-Control-Allow-Credentials: true
```

## 10. Webhook Support (Optional)

### 10.1 Registration Webhook

**Endpoint**: Configurable webhook URL

**Payload**:
```json
{
  "event": "credential.registered",
  "timestamp": "2023-12-01T10:00:00Z",
  "user": {
    "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "username": "user@example.com"
  },
  "credential": {
    "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "type": "public-key",
    "aaguid": "AAAAAAAAAAAAAAAAAAAAAA"
  }
}
```

### 10.2 Authentication Webhook

**Payload**:
```json
{
  "event": "credential.authenticated",
  "timestamp": "2023-12-01T10:05:00Z",
  "user": {
    "id": "dXNlci1pZC1iYXNlNjR1cmwtZW5jb2RlZA",
    "username": "user@example.com"
  },
  "credential": {
    "id": "YmFzZTY0dXJsLWVuY29kZWQtY3JlZGVudGlhbC1pZA",
    "signCount": 123
  },
  "authentication": {
    "userVerified": true,
    "ipAddress": "192.168.1.100",
    "userAgent": "Mozilla/5.0..."
  }
}
```

This API specification provides a comprehensive foundation for implementing a FIDO2/WebAuthn conformant server that is compatible with the FIDO Alliance Conformance Test Tools while maintaining security best practices and extensibility for future requirements.