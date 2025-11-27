# FIDO Server

A FIDO2/WebAuthn compliant server implementation in Rust, built with Actix-web, PostgreSQL, and Redis.

## Features

- 🔐 **FIDO2/WebAuthn** compliant implementation
- 🚀 **High Performance** with Actix-web framework
- 🗄️ **PostgreSQL** database with connection pooling
- ⚡ **Redis** for session state management
- 🛡️ **Security First** design with comprehensive error handling
- ✅ **Health Monitoring** endpoint for service status
- 📊 **Structured Logging** with configurable levels
- 🔧 **Environment-based Configuration**

## Quick Start

### Prerequisites

- Rust 1.70+ 
- PostgreSQL 12+
- Redis 6+

### Configuration

Copy the example environment file and update with your settings:

```bash
cp .env.example .env
```

Required environment variables:

```bash
# Database
FIDO_DATABASE_URL=postgresql://username:password@localhost:5432/fido_server

# Redis  
FIDO_REDIS_URL=redis://localhost:6379

# Server
FIDO_SERVER_HOST=127.0.0.1
FIDO_SERVER_PORT=8080

# WebAuthn
FIDO_WEBAUTHN_RP_ID=localhost
FIDO_WEBAUTHN_RP_NAME=FIDO Server
FIDO_WEBAUTHN_ORIGIN=http://localhost:8080
```

### Running the Server

```bash
# Development
cargo run

# Release
cargo build --release
./target/release/fido-server
```

The server will start at `http://localhost:8080`

### Health Check

Check server status:

```bash
curl http://localhost:8080/health
```

**Success Response (200 OK):**
```json
{
  "status": "ok",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "0.1.0",
  "database": "connected",
  "redis": "connected"
}
```

**Error Response (503 Service Unavailable):**
```json
{
  "status": "error",
  "errorMessage": "Database connection failed"
}
```

## Architecture

### Base Framework Components

- **Configuration Management**: Environment-based configuration with validation
- **Database Layer**: PostgreSQL with Diesel ORM and r2d2 connection pooling
- **Redis Layer**: Connection pooling with deadpool-redis
- **Application State**: Thread-safe state management with Arc-wrapped pools
- **Error Handling**: FIDO2-compliant JSON error responses
- **Health Monitoring**: Comprehensive service health checking

### Security Features

- **Secure Headers**: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, HSTS
- **SSL/TLS**: Configurable database and Redis SSL modes
- **Error Sanitization**: No sensitive information in error responses
- **Configuration Validation**: Environment variable validation at startup

### Directory Structure

```
src/
├── main.rs              # Application entry point
├── lib.rs               # Library exports
├── config/              # Configuration management
├── controllers/         # HTTP handlers
├── db/                  # Database connection and models
├── error/               # Error types and handling
├── middleware/          # Custom middleware
├── redis.rs             # Redis connection management
├── routes/              # Route configuration
├── schema/              # Database schema
├── services/            # Business logic
├── state.rs             # Application state
└── utils/               # Utility functions
```

## Development

### Running Tests

```bash
# All tests
cargo test

# Specific test
cargo test test_health_endpoint

# With output
cargo test -- --nocapture
```

### Code Quality

```bash
# Linting
cargo clippy

# Formatting
cargo fmt

# Documentation
cargo doc --open
```

### Environment Setup

For development, you can use the provided test configuration:

```bash
# Copy test environment
cp .env .env.local

# Start with mock services (when database/redis unavailable)
# The health endpoint will return appropriate error status
```

## API Endpoints

### Health Check

- **GET** `/health`
- **Description**: Returns service health status
- **Authentication**: None required
- **Response**: JSON with service status information

### Future Endpoints

The base framework is ready for FIDO2/WebAuthn endpoints:

- **POST** `/auth/register/begin` - Start registration ceremony
- **POST** `/auth/register/finish` - Complete registration ceremony  
- **POST** `/auth/authenticate/begin` - Start authentication ceremony
- **POST** `/auth/authenticate/finish` - Complete authentication ceremony

## Configuration Options

### Database Settings

```bash
FIDO_DATABASE_URL              # PostgreSQL connection string
FIDO_DATABASE_MAX_POOL_SIZE    # Connection pool size (default: 10)
FIDO_DATABASE_TIMEOUT_SECONDS  # Connection timeout (default: 30)
FIDO_DATABASE_IDLE_TIMEOUT_SECONDS # Idle timeout (default: 600)
FIDO_DATABASE_SSL_MODE         # SSL mode: require/prefer/allow/disable
```

### Redis Settings

```bash
FIDO_REDIS_URL                     # Redis connection string
FIDO_REDIS_MAX_SIZE                # Pool size (default: 10)
FIDO_REDIS_TIMEOUT_SECONDS         # Connection timeout (default: 30)
FIDO_REDIS_RECYCLE_TIMEOUT_SECONDS # Recycle timeout (default: 300)
```

### Server Settings

```bash
FIDO_SERVER_HOST    # Bind address (default: 127.0.0.1)
FIDO_SERVER_PORT    # Port number (default: 8080)
```

### WebAuthn Settings

```bash
FIDO_WEBAUTHN_RP_ID    # Relying Party ID
FIDO_WEBAUTHN_RP_NAME  # Relying Party Display Name
FIDO_WEBAUTHN_ORIGIN   # Expected origin for ceremonies
```

## Error Handling

All API responses follow FIDO2-compliant JSON error format:

```json
{
  "status": "error",
  "errorMessage": "Human-readable error description"
}
```

Error types:
- `400 Bad Request` - Invalid input or WebAuthn errors
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Database/Redis connection errors
- `503 Service Unavailable` - Service health check failures

## Logging

Structured logging with configurable levels:

```bash
# Environment variable
RUST_LOG=info              # error, warn, info, debug, trace

# Examples
RUST_LOG=debug             # Debug level
RUST_LOG=fido_server=trace # Trace for this crate only
```

## Production Deployment

### Recommended Settings

```bash
# Production environment
RUN_MODE=production

# SSL enforcement
FIDO_DATABASE_SSL_MODE=require

# Security headers
# (automatically configured in production mode)
```

### Health Monitoring

Use the `/health` endpoint for:
- Load balancer health checks
- Monitoring system alerts
- Service dependency verification

### Performance Considerations

- Database connection pool sizing based on concurrent load
- Redis connection pool optimization
- SSL/TLS configuration for production
- Log level adjustment for performance

## Contributing

1. Follow Rust best practices and idioms
2. Maintain test coverage
3. Update documentation for API changes
4. Follow FIDO2/WebAuthn specifications strictly
5. Security-first approach for all changes

## License

MIT License - see LICENSE file for details.