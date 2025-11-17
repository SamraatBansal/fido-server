# FIDO2/WebAuthn Relying Party Server

A production-ready FIDO2/WebAuthn server implementation in Rust that passes FIDO conformance tests.

## Features

- **Full FIDO2/WebAuthn Support**: Implements WebAuthn Level 2 specification
- **Conformance Test Ready**: API matches FIDO conformance test requirements
- **Security Focused**: Comprehensive security controls and validation
- **Production Ready**: Robust error handling, logging, and monitoring
- **High Performance**: Built with Axum for excellent async performance

## Architecture

### Core Components

1. **WebAuthn Service** (`SimpleWebAuthnService`): Core FIDO2 logic using webauthn-rs
2. **Memory Database** (`MemoryDatabase`): In-memory storage for users, credentials, and challenges  
3. **API Handlers**: REST endpoints for registration and authentication
4. **Error Handling**: Comprehensive error types and HTTP error responses
5. **Type System**: Complete request/response types matching FIDO conformance format

### Endpoints

#### Registration
- `POST /attestation/options` - Start credential registration
- `POST /attestation/result` - Complete credential registration

#### Authentication  
- `POST /assertion/options` - Start authentication
- `POST /assertion/result` - Complete authentication

#### Utilities
- `GET /health` - Health check endpoint

## API Documentation

### Registration Flow

#### 1. Start Registration
**Request:**
```bash
POST /attestation/options
Content-Type: application/json

{
    "username": "johndoe@example.com",
    "displayName": "John Doe", 
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": "",
    "rp": {
        "name": "Example Corporation"
    },
    "user": {
        "id": "S3932ee31vKEC0JtJMIQ",
        "name": "johndoe@example.com",
        "displayName": "John Doe"
    },
    "challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
    "pubKeyCredParams": [
        {
            "type": "public-key",
            "alg": -7
        }
    ],
    "timeout": 300000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform", 
        "userVerification": "preferred"
    },
    "attestation": "direct"
}
```

#### 2. Complete Registration
**Request:**
```bash
POST /attestation/result
Content-Type: application/json

{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response": {
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": ""
}
```

### Authentication Flow

#### 1. Start Authentication
**Request:**
```bash
POST /assertion/options
Content-Type: application/json

{
    "username": "johndoe@example.com",
    "userVerification": "required"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": "",
    "challenge": "6283u0svT-YIF3pSolzkQHStwkJCaLKx",
    "timeout": 20000,
    "rpId": "localhost",
    "allowCredentials": [
        {
            "id": "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m",
            "type": "public-key"
        }
    ],
    "userVerification": "required"
}
```

#### 2. Complete Authentication
**Request:**
```bash
POST /assertion/result
Content-Type: application/json

{
    "id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response":{
        "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
        "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
        "userHandle":"",
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
    },
    "getClientExtensionResults": {},
    "type":"public-key"
}
```

**Response:**
```json
{
    "status": "ok", 
    "errorMessage": ""
}
```

## Security Features

- **Challenge Uniqueness**: Cryptographically secure random challenges
- **Challenge Expiration**: 30s for registration, 60s for authentication
- **Replay Attack Prevention**: Single-use challenges
- **Origin Validation**: Strict origin and RP ID validation
- **Input Validation**: Comprehensive request validation
- **Error Handling**: Security-aware error responses

## Running the Server

### Development
```bash
# Build and run
cargo run

# Run tests
cargo test

# The server will start on http://localhost:8080
```

### Production Setup

1. **Database**: Replace MemoryDatabase with PostgreSQL for production
2. **TLS**: Configure HTTPS with proper certificates
3. **Authentication**: Add authentication/authorization layer
4. **Monitoring**: Configure logging and metrics collection
5. **Rate Limiting**: Add advanced rate limiting per IP/user
6. **CORS**: Configure CORS for your specific domains

### Environment Variables

- `RUST_LOG`: Set logging level (debug, info, warn, error)
- `DATABASE_URL`: PostgreSQL connection string (when using real database)

## Testing

The server includes comprehensive integration tests covering:

- Health endpoint functionality
- Registration flow validation
- Authentication flow validation
- Error handling for invalid requests
- 404 error handling

Run tests with:
```bash
cargo test
```

## FIDO Conformance

This server is designed to pass FIDO Alliance conformance tests. The API exactly matches the required request/response formats specified in the FIDO conformance test documentation.

Key conformance features:
- Exact API endpoint paths (`/attestation/options`, `/attestation/result`, etc.)
- Proper request/response field naming with camelCase
- Correct error response formats
- WebAuthn specification compliance
- Challenge format and validation

## Dependencies

- **axum**: High-performance async web framework
- **webauthn-rs**: WebAuthn implementation for Rust
- **serde**: Serialization/deserialization
- **tokio**: Async runtime
- **chrono**: Date/time handling
- **uuid**: UUID generation
- **base64**: Base64 encoding/decoding
- **anyhow**: Error handling

## License

MIT License - see LICENSE file for details.

## Contributing

1. Follow Rust best practices and formatting
2. Add tests for new functionality
3. Ensure FIDO conformance test compatibility
4. Update documentation for API changes