# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-07-25

Initial release. Extracts the byte-identical OIDC-client code previously
duplicated across the `proxy` and `jump-host` theta42 apps into a single
factory-based package.

### Added
- `createOidcClient({ Table, checkApiToken? })` factory that wires the shared
  OIDC authorization-code + PKCE client onto an app's model-redis `Table`:
  - `Token` / `AuthToken` session models (extend the caller's `Table`,
    registered under their literal names; `AuthToken` carries the login-time
    group snapshot).
  - `OidcState` short-lived PKCE/state store (5-minute TTL).
  - `Auth` service: `login`, `oidcSession` (JIT provision), `checkToken`,
    `logout`, and optional `checkApiToken` (wrapped to collapse every failure
    to a generic `401 LoginFailed` — no existence/secret/expiry leak).
  - Express `router` (`POST /login`, `ALL /logout`, `GET /oidc/start`,
    `GET /oidc/callback`) with per-IP rate limiting.
  - Pure `oidc` utils (`randomToken`, `codeChallengeS256`, `createAuthRequest`,
    `buildAuthUrl`, `exchangeCode`, `fetchUserInfo`, `claimsToIdentity`).
  - `safeInternalPath` redirect sanitizer.
  - `bootstrapLocalAdmin(User, { defaultName })` anti-lockout admin bootstrap.
- `node --test` unit suite (PKCE encoding, redirect sanitization, factory
  contract, `checkApiToken` error-collapse).

### Notes
- Per-app `middleware/auth.js` and proxy's per-host `routes/host_auth.js` stay
  app-local; they consume `Auth` and the pure `oidc` utils from this package.