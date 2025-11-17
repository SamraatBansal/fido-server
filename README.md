# FIDO2/WebAuthn Relying Party Server

A production-ready FIDO2/WebAuthn Relying Party Server implementation in Rust that passes FIDO Alliance conformance tests.

## Features

- ✅ **Full FIDO2/WebAuthn Support**: Implements complete registration and authentication flows
- ✅ **FIDO Conformance**: Designed to pass FIDO Alliance conformance test tools
- ✅ **Production Ready**: PostgreSQL database, proper error handling, security headers
- ✅ **Secure by Design**: Uses webauthn-rs library for cryptographic operations
- ✅ **REST API**: Standard REST endpoints following FIDO test specifications
- ✅ **Docker Support**: Easy deployment with PostgreSQL container

## API Endpoints

The server implements the FIDO Alliance test specification endpoints:

### Registration Flow
- `POST /attestation/options` - Start credential registration
- `POST /attestation/result` - Complete credential registration

### Authentication Flow  
- `POST /assertion/options` - Start authentication
- `POST /assertion/result` - Complete authentication

### Additional Endpoints
- `GET /health` - Health check endpoint

## Quick Start

### Prerequisites

- Rust 1.70+ 
- Docker and Docker Compose
- curl and jq (for testing)

### 1. Start the Database

```bash
docker-compose up -d postgres
```

### 2. Start the Server

```bash
# Using the startup script (recommended)
./start_dev.sh

# Or manually
cargo run
```

The server will start on http://localhost:8080

### 3. Test the API

```bash
./test_endpoints.sh
```

## Configuration

Configuration is handled via environment variables or `.env` file:

```bash
# Database Configuration
DATABASE_URL=postgresql://fido_user:fido_password@localhost:5432/fido_db

# Server Configuration
PORT=8080
ORIGIN_URL=http://localhost:8080
RP_ID=localhost
RP_NAME="Example Corporation"
```

## API Usage Examples

### Registration Flow

#### 1. Start Registration
```bash
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "displayName": "John Doe",
    "authenticatorSelection": {
      "requireResidentKey": false,
      "authenticatorAttachment": "cross-platform",
      "userVerification": "preferred"
    },
    "attestation": "direct"
  }'
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
    "id": "dXNlcjEyMw",
    "name": "user@example.com", 
    "displayName": "John Doe"
  },
  "challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ],
  "timeout": 10000,
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
```bash
curl -X POST http://localhost:8080/attestation/result \
  -H "Content-Type: application/json" \
  -d '{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26",
    "response": {
      "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ1aFVqUE5sWmZ2bjdvbnd1aE5kc0xQa2tFNUZ2LWxVTiIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
      "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge"
    },
    "type": "public-key",
    "getClientExtensionResults": {}
  }'
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
```bash
curl -X POST http://localhost:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "userVerification": "required"
  }'
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
```bash
curl -X POST http://localhost:8080/assertion/result \
  -H "Content-Type: application/json" \
  -d '{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26",
    "response": {
      "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
      "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
      "userHandle": "",
      "clientDataJSON": "eyJjaGFsbGVuZ2UiOiI2MjgzdTBzdlQtWUlGM3BTb2x6a1FIU3R3a0pDYUxLeCIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ"
    },
    "type": "public-key",
    "getClientExtensionResults": {}
  }'
```

**Response:**
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

## FIDO Conformance Testing

This server is designed to pass FIDO Alliance conformance tests. The API follows the exact format specified in the FIDO conformance documentation.

### Running Conformance Tests

1. Start the server: `./start_dev.sh`
2. Configure your FIDO conformance tool to point to `http://localhost:8080`
3. Run the conformance test suite

### Supported Features

- ✅ ES256, PS256, EdDSA algorithms
- ✅ Attestation formats: none, self, basic
- ✅ User verification levels
- ✅ Resident key support
- ✅ Authenticator attachment preferences
- ✅ Timeout management
- ✅ Origin validation
- ✅ Challenge uniqueness and entropy
- ✅ Counter regression detection

## Architecture

### Components

- **WebAuthn Service**: Core FIDO2 logic using webauthn-rs
- **Database Layer**: PostgreSQL with SQLx for credential storage
- **API Handlers**: Axum REST endpoints
- **Security Middleware**: CORS, timeouts, rate limiting
- **Error Handling**: Comprehensive error responses

### Security Features

- 🔒 **TLS Enforcement**: HTTPS required in production
- 🔒 **CORS Protection**: Configurable origin validation  
- 🔒 **Input Validation**: Comprehensive request validation
- 🔒 **Challenge Security**: Cryptographically secure challenges
- 🔒 **Counter Regression**: Prevents cloned authenticator attacks
- 🔒 **Origin Validation**: Strict RP ID and origin checking

### Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Credentials table
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    attestation_format VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Challenge tables for state management
CREATE TABLE registration_challenges (...);
CREATE TABLE authentication_challenges (...);
```

## Production Deployment

### Environment Configuration

```bash
# Production settings
DATABASE_URL=postgresql://user:pass@prod-db:5432/fido_db
PORT=8080
ORIGIN_URL=https://your-domain.com
RP_ID=your-domain.com
RP_NAME="Your Company"
RUST_LOG=info
```

### Security Checklist

- [ ] Use HTTPS in production
- [ ] Configure proper CORS origins
- [ ] Use strong database credentials
- [ ] Enable proper logging and monitoring
- [ ] Set up database backups
- [ ] Configure rate limiting
- [ ] Use reverse proxy (nginx/Cloudflare)

## Development

### Project Structure

```
src/
├── main.rs          # Server entry point
├── lib.rs           # Module declarations
├── error.rs         # Error handling
├── types.rs         # Data models and API types
├── db.rs            # Database layer
├── webauthn.rs      # WebAuthn service
├── handlers.rs      # API endpoint handlers
└── simple_webauthn.rs # Simplified WebAuthn for testing
```

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy
cargo fmt
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

- File issues on GitHub
- Check the FIDO Alliance specifications
- Review the webauthn-rs documentation