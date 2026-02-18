# OAuth 2.0 / OIDC Authorization Server

A production-grade OAuth 2.0 and OpenID Connect authorization server built from scratch in Java with Spring Boot. This implementation handles all OAuth logic manually — every token, every validation, every spec-compliant behavior — without relying on Spring Security OAuth2 Authorization Server.

## Overview

This project implements a fully spec-compliant authorization server supporting:

- **OAuth 2.0 Grant Types**
  - Authorization Code Grant (RFC 6749)
  - Client Credentials Grant (RFC 6749)
  - Refresh Token Grant (RFC 6749)
  - Device Authorization Grant (RFC 8628)

- **OpenID Connect**
  - ID Token generation
  - UserInfo endpoint
  - Discovery document (`.well-known/openid-configuration`)

- **Security Features**
  - PKCE (RFC 7636) — required for public clients, recommended for all
  - JWT access tokens with RS256 signing
  - JWKS endpoint for public key distribution
  - Token introspection (RFC 7662)
  - Token revocation (RFC 7009)
  - Refresh token rotation with reuse detection

## Tech Stack

- **Java 21**
- **Spring Boot 4.0.2**
- **PostgreSQL** — backing datastore
- **Flyway** — database migrations
- **Nimbus JOSE+JWT** — JWT signing and verification
- **Spring Data JPA** — data access
- **Spring Validation** — request validation
- **Lombok** — boilerplate reduction

## Prerequisites

- Java 21+
- PostgreSQL
- Maven 3.9+
- Docker (optional, for containerized PostgreSQL)

## Getting Started

### 1. Clone the repository

```bash
git clone <repository-url>
cd authserver
```

### 2. Set up PostgreSQL

Using Docker Compose:

```bash
docker-compose up -d
```

Or configure your own PostgreSQL instance and update `application.properties`.

### 3. Build and run

```bash
./mvnw spring-boot:run
```

## Project Structure

```
src/main/java/com/rackleet/authserver/
├── config/        # Spring configuration classes
├── controller/    # HTTP endpoints
├── crypto/        # Key management, signing, hashing utilities
├── dto/           # Request/response objects
├── entity/        # JPA entities
├── exception/     # Custom exceptions and error handling
├── repository/    # Spring Data JPA repositories
├── security/      # Request filters, authentication logic
└── service/       # Business logic
```

## API Endpoints

### OAuth 2.0 / OIDC Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /oauth2/authorize` | Authorization endpoint |
| `POST /oauth2/token` | Token endpoint |
| `POST /oauth2/revoke` | Token revocation |
| `POST /oauth2/introspect` | Token introspection |
| `GET /oauth2/jwks` | JSON Web Key Set |
| `GET /oauth2/userinfo` | UserInfo endpoint |
| `POST /oauth2/device_authorization` | Device authorization |
| `GET /.well-known/openid-configuration` | OIDC Discovery |

### Admin API

| Endpoint | Description |
|----------|-------------|
| `POST /api/clients` | Register a new client |
| `GET /api/clients/{clientId}` | Get client metadata |
| `PUT /api/clients/{clientId}` | Update client |
| `DELETE /api/clients/{clientId}` | Deactivate client |
| `POST /api/users/register` | Register a user |

## Supported Specifications

- RFC 6749 — OAuth 2.0 Authorization Framework
- RFC 6750 — Bearer Token Usage
- RFC 7009 — Token Revocation
- RFC 7517 — JSON Web Key (JWK)
- RFC 7519 — JSON Web Token (JWT)
- RFC 7636 — Proof Key for Code Exchange (PKCE)
- RFC 7662 — Token Introspection
- RFC 8414 — Authorization Server Metadata
- RFC 8628 — Device Authorization Grant
- OpenID Connect Core 1.0
- OpenID Connect Discovery 1.0

## Development

### Running tests

```bash
./mvnw test
```

### Building

```bash
./mvnw clean package
```

## License

See [LICENSE](LICENSE) for details.
