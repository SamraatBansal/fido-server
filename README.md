# FIDO Server

A FIDO2/WebAuthn conformant server written in Rust for secure passkey management.

## Features

- 🔐 FIDO2/WebAuthn compliant passkey registration
- 🔑 Passkey-based authentication
- 🗄️ PostgreSQL database for credential storage
- 🚀 High-performance async server with Actix-web
- ✅ Comprehensive test coverage
- 🛡️ Strict linting and code quality checks

## Prerequisites

- Rust 1.70 or higher
- PostgreSQL 14 or higher
- Cargo

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd fido-server
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials
```

3. Install dependencies:
```bash
cargo build
```

4. Run database migrations:
```bash
diesel migration run
```

## Development

### Running the server

```bash
cargo run
```

### Running tests

```bash
cargo test
```

### Code formatting

```bash
cargo fmt
```

### Linting

```bash
cargo clippy -- -D warnings
```

### Strict checks

```bash
cargo check-strict
```

## API Endpoints

### Health Check
- `GET /health` - Server health status

### Registration
- `POST /api/register/start` - Initiate passkey registration
- `POST /api/register/finish` - Complete passkey registration

### Authentication
- `POST /api/authenticate/start` - Initiate passkey authentication
- `POST /api/authenticate/finish` - Complete passkey authentication

## Project Structure

```
fido-server/
├── src/
│   ├── controllers/    # Request handlers
│   ├── db/            # Database models and connection
│   ├── routes/        # API route definitions
│   ├── schema/        # Request/Response schemas
│   ├── services/      # Business logic
│   ├── middleware/    # Custom middleware
│   ├── error/         # Error types
│   └── utils/         # Utility functions
└── tests/            # Integration tests
```

## License

MIT
