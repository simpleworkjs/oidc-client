# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] — 2026-09-13

### Fixed
- **A discovery failure no longer breaks login.** In 1.1.0, a configured
  `issuer` whose discovery document could not be read caused
  `verifyIdTokenIfPossible()` to throw — so upgrading would break every login on
  a deployment whose issuer is set but not reachable from where this code runs.
  theta42's proxy is exactly that shape: `issuer` points at the public HTTPS
  host, while `tokenEndpoint` and `userinfoEndpoint` deliberately use an internal
  container address. Discovery from inside the container can fail, and 1.1.0
  turned that into a total outage rather than the previous behaviour.

  A discovery attempt that fails now means "we never established that this
  provider can be verified against" — the same position as a provider with no
  JWKS — so it warns once and falls back to userinfo-only identity. Set
  `conf.oidc.jwksUri` explicitly to turn verification on where the issuer is not
  reachable from the app.

  **Unchanged:** once discovery HAS produced a JWKS, failing to use it is still
  fatal. That is a provider we know we should be able to verify against, and
  failing open there would be the silent skip this feature exists to avoid.

## [1.1.0] — 2026-09-13

### Added
- **OpenID Connect Discovery.** Set `conf.oidc.issuer` and the authorization,
  token, userinfo, JWKS, revocation and end-session endpoints are read from the
  provider's `/.well-known/openid-configuration` instead of being configured one
  by one. Fetched once at startup and cached; every path that needs an endpoint
  retries lazily, so a provider that is briefly unreachable at boot does not
  wedge logins. A discovery document advertising a different `issuer` than the
  one configured is refused (OIDC Discovery 1.0 §4.3) — otherwise it could point
  us at someone else's endpoints.
- **ID-token verification.** `verifyIdToken()` checks the signature against the
  provider's JWKS (RS/PS/ES 256/384/512; `alg: none` and anything unlisted are
  refused), then `iss`, `aud`, `exp` and `nbf` with a 60s clock tolerance. An
  unknown `kid` refetches the key set immediately rather than waiting out the
  cache, so a key rotation does not mean an hour of failed logins.
- The callback route now verifies the ID token when the provider publishes a
  JWKS, and **cross-checks its subject against userinfo** — the identity acted on
  has to be the one that was signed for.

### Changed
- Endpoints are resolved through `endpoints()`: explicitly configured values
  always win over discovered ones, so a deployment that lists them by hand is
  unaffected.
- `verifyIdTokenIfPossible()` returns `null` with a **one-time warning** when no
  JWKS is available, preserving the previous userinfo-only behaviour for a
  provider that publishes none. A provider that *does* publish one and fails
  verification is an error, not a skip.

### Why now

This client shipped with a comment explaining that it did not verify ID-token
signatures because "the SSO publishes no jwks_uri" — identity came from the
userinfo endpoint alone, which is sound but establishes nothing about who
asserted it. theta-directory v2.38.0 publishes a JWKS, so the constraint is
gone. Existing deployments keep working untouched; adding `issuer` to their
`conf.oidc` is what turns verification on.

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