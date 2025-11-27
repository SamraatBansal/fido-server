# FIDO Server

A FIDO2/WebAuthn compliant server implementation in Rust with Actix-web, PostgreSQL, and Redis.

## Features

- **FIDO2/WebAuthn Compliance**: Full implementation following FIDO Alliance specifications
- **Secure Architecture**: Thread-safe design with proper connection pooling
- **Health Monitoring**: Built-in health check endpoint for monitoring and load balancers
- **Environment Configuration**: Flexible configuration through environment variables
- **Structured Error Handling**: Consistent JSON error responses
- **High Performance**: Built with Actix-web for maximum throughput

## Architecture

### Technology Stack

- **Web Framework**: Actix-web 4.x
- **Database**: PostgreSQL with Diesel ORM and r2d2 connection pooling
- **Cache/Sessions**: Redis with deadpool-redis connection pooling
- **WebAuthn**: webauthn-rs library for FIDO2/WebAuthn implementation
- **Serialization**: Serde for JSON handling
- **Configuration**: Environment-based configuration with dotenv support
- **Logging**: Structured logging with env_logger

### Project Structure

```
src/
├── main.rs              # Server entry point
├── lib.rs               # Library exports
├── config/              # Configuration management
│   ├── mod.rs
│   └── settings.rs      # Environment-based settings
├── controllers/         # HTTP request handlers
│   ├── mod.rs
│   ├── health.rs        # Health check endpoint
│   ├── authentication.rs # WebAuthn authentication (TODO)
│   └── registration.rs  # WebAuthn registration (TODO)
├── db/                  # Database layer
│   ├── mod.rs
│   ├── connection.rs    # PostgreSQL connection pool
│   └── models.rs        # Database models
├── error/               # Error handling
│   ├── mod.rs
│   └── types.rs         # Error types and JSON formatting
├── redis.rs             # Redis connection and session management
├── routes/              # URL routing
│   ├── mod.rs
│   └── api.rs           # API route configuration
├── state.rs             # Thread-safe application state
└── ...                  # Additional modules
```

## Quick Start

### Prerequisites

- Rust 1.70+ with Cargo
- PostgreSQL 13+
- Redis 6.0+

### Installation

1. **Clone and build**:
   ```bash
   git clone <repository>
   cd fido-server
   cargo build --release
   ```

2. **Set up environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Configure services**:
   - Set up PostgreSQL database
   - Set up Redis instance
   - Update connection URLs in `.env`

4. **Run the server**:
   ```bash
   cargo run --bin fido-server
   ```

The server will start on `http://localhost:8080` by default.

## Configuration

The server is configured through environment variables. See `.env.example` for all available options:

### Server Configuration
- `SERVER_HOST` - Server bind address (default: 127.0.0.1)
- `SERVER_PORT` - Server port (default: 8080)

### Database Configuration
- `DATABASE_URL` - PostgreSQL connection URL (required)
- `DATABASE_MAX_POOL_SIZE` - Maximum connection pool size (default: 10)
- `DATABASE_CONNECTION_TIMEOUT` - Connection timeout in seconds (default: 5)
- `DATABASE_IDLE_TIMEOUT` - Idle timeout in seconds (default: 600)

### Redis Configuration
- `REDIS_URL` - Redis connection URL (required)
- `REDIS_MAX_POOL_SIZE` - Maximum connection pool size (default: 5)
- `REDIS_CONNECTION_TIMEOUT` - Connection timeout in seconds (default: 5)
- `REDIS_COMMAND_TIMEOUT` - Command timeout in seconds (default: 3)
- `REDIS_SESSION_TTL` - Session TTL in seconds (default: 300)

### WebAuthn Configuration
- `WEBAUTHN_RP_ID` - Relying Party ID (default: localhost)
- `WEBAUTHN_RP_NAME` - Relying Party name (default: FIDO Server)
- `WEBAUTHN_ORIGIN` - Origin URL (default: http://localhost:8080)

## API Endpoints

### Health Check

**GET** `/health`

Returns the health status of the server and its dependencies.

**Response (200 OK)**:
```json
{
  \"status\": \"ok\",
  \"timestamp\": \"2024-01-15T10:30:00Z\",
  \"services\": {
    \"database\": \"connected\",
    \"redis\": \"connected\"
  },
  \"version\": \"1.0.0\"
}
```

**Response (503 Service Unavailable)**:
```json
{
  \"status\": \"error\",
  \"errorMessage\": \"Service unavailable - database connection failed\"
}
```

### Testing the Health Endpoint

```bash
curl -X GET http://localhost:8080/health -H \"Content-Type: application/json\"
```

## Development

### Building

```bash
# Check compilation
cargo check

# Build debug version
cargo build

# Build release version
cargo build --release

# Run with logging
RUST_LOG=debug cargo run
```

### Testing

```bash
# Run tests
cargo test

# Run with coverage
cargo test --coverage

# Run integration tests
cargo test --test integration
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint code
cargo clippy

# Check for security issues
cargo audit
```

## Security Features

- **Connection Pool Security**: Configured with appropriate limits and timeouts
- **Error Response Security**: Generic error messages without internal details
- **Thread Safety**: All shared state wrapped in Arc for safe concurrent access
- **Input Validation**: Comprehensive validation of configuration and requests
- **Session Management**: Secure Redis-based session storage with TTL

## Production Deployment

### Security Checklist

1. **TLS Configuration**: Use HTTPS/TLS for all production traffic
2. **Database Security**: Enable SSL/TLS for database connections
3. **Redis Security**: Use authentication and encryption for Redis
4. **Environment Variables**: Never commit secrets to version control
5. **Logging**: Ensure no sensitive data is logged
6. **Monitoring**: Set up health check monitoring and alerting

### Environment Configuration

```bash
# Production environment example
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
DATABASE_URL=postgresql://user:pass@db.example.com:5432/fido_prod?sslmode=require
REDIS_URL=rediss://auth:token@redis.example.com:6380
WEBAUTHN_RP_ID=example.com
WEBAUTHN_ORIGIN=https://example.com
RUST_LOG=info
```

### Docker Deployment

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /app/target/release/fido-server /usr/local/bin/
EXPOSE 8080
CMD [\"fido-server\"]
```

## Contributing

1. Follow the existing code style and patterns
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all security requirements are met

## License

MIT License - see LICENSE file for details.