# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Java SAML toolkit (forked from SAML-Toolkits/java-saml, maintained by CodeLibs) implementing SAML 2.0 SP operations. Multi-module Maven project targeting Java 11+.

## Build Commands

```bash
mvn clean package                              # Build all modules with tests
mvn clean package -DskipTests                  # Build without tests
mvn test                                       # Run all tests
mvn test -pl core                              # Run core module tests only
mvn test -pl toolkit                           # Run toolkit module tests only
mvn test -Dtest=AuthnRequestTest               # Run single test class
mvn test -Dtest=AuthnRequestTest#testMethod    # Run single test method
```

No code formatter or linter is configured. CI runs `mvn -B package` on Java 11/Ubuntu via GitHub Actions.

## Module Structure

- **core** (`java-saml-core`) — Low-level SAML 2.0 operations: building/parsing/validating AuthnRequests, Responses, LogoutRequests, LogoutResponses, metadata, XML signing/encryption
- **toolkit** (`java-saml`) — High-level servlet-based API wrapping core; depends on Jakarta Servlet 6.0
- **samples** — Example JSP application (not published)

## Architecture

### SAML Flow (SSO)

`Auth.login()` → builds `AuthnRequest` → redirect to IdP → IdP posts `SamlResponse` to ACS → `Auth.processResponse()` validates and extracts attributes/NameID

### Key Classes

- **`Auth`** (toolkit) — Stateful, per-request SP orchestration. Not thread-safe. Entry point for `login()`, `logout()`, `processResponse()`, `processSLO()`.
- **`Saml2Settings`** — Immutable configuration container (SP entity, IdP entity, certificates, security flags). Built via `SettingsBuilder` from properties files or `Map<String, Object>`.
- **`AuthnRequest` / `SamlResponse` / `LogoutRequest` / `LogoutResponse`** (core) — SAML message builders/parsers.
- **`HttpRequest`** — Framework-agnostic HTTP request abstraction. `ServletUtils.makeHttpRequest()` converts `HttpServletRequest` to this.
- **`SamlMessageFactory`** — Factory interface for customizing SAML message creation (extend to override default message classes).
- **`Constants`** — All SAML protocol constants (NameID formats, bindings, status codes, algorithms).
- **`Util`** — XML manipulation, cryptographic operations, certificate loading.

### Configuration

Settings loaded from `onelogin.saml.properties` on classpath or programmatically via `SettingsBuilder.fromValues(Map)`. Properties prefixed with `onelogin.saml2.*`. KeyStore-based configuration also supported via `KeyStoreSettings`.

### Security Defaults

SHA-256 digest, RSA-SHA256 signatures, 120s clock drift tolerance. `strict` mode must be TRUE in production. Deprecated algorithms (SHA-1) rejected by default.

## Test Resources

Test data lives in `core/src/test/resources/`:
- `config/` — 30+ configuration profiles for different test scenarios
- `data/` — Pre-built SAML XML messages (responses, requests, metadata)
- `certs/` — Test certificates and private keys

Tests use JUnit 4 + Mockito 5.
