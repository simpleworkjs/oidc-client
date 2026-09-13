# @simpleworkjs/oidc-client

Shared OpenID Connect (authorization-code + PKCE) client for the **theta42** operational apps — `proxy` and `jump-host`. Both apps carried byte-identical copies of the OIDC handshake, the short-lived state store, the session-token models, the local-login / OIDC-session `Auth` service, the auth router, the safe-redirect helper, and the anti-lockout local-admin bootstrap. This package is that code, extracted once.

It is a **factory**, not a load-and-go module: the session models extend the consuming app's model-redis `Table` (so they share that app's redis connection, key prefix, and model registry), and `Auth` binds to that app's `User` model.

## Install

```sh
npm install @simpleworkjs/oidc-client
```

## Usage

```js
const { createOidcClient } = require('@simpleworkjs/oidc-client');
const { setUpTable } = require('model-redis');
const conf = require('@simpleworkjs/conf');

const Table = setUpTable(conf.redis);
require('./user_redis');            // registers `User` on Table.models

const {
  Token, AuthToken, OidcState, Auth, router: authRouter,
  oidc, safeInternalPath, bootstrapLocalAdmin,
} = createOidcClient({
  Table,
  // Optional — only for apps that accept Bearer PATs (proxy). Omit for jump-host.
  checkApiToken: (raw) => ApiToken.authenticate(raw),
});

// Mount the auth router: POST /login, ALL /logout, GET /oidc/start, GET /oidc/callback
app.use('/api/auth', authRouter);

// JIT the anti-lockout local admin (idempotent, fire-and-forget).
bootstrapLocalAdmin(Table.models.User, { defaultName: 'proxyadmin2' });
```

### What stays app-local

- **`middleware/auth.js`** — turns a session token (and, for proxy, a Bearer PAT) into `req.token` / `req.user`. It differs per app (proxy has PATs + admin gating; jump-host has admin gating only), so it is not shared. It consumes `Auth` from this package.
- **proxy's `routes/host_auth.js`** — per-host SSO endpoints. It consumes the exported pure `oidc` utils (`createAuthRequest`, `buildAuthUrl`, `exchangeCode`, `fetchUserInfo`, `claimsToIdentity`, `randomToken`) directly.

## API

### `createOidcClient({ Table, checkApiToken? })`

- `Table` *(required)* — the app's model-redis `Table` base class. `User` **must** be registered on `Table.models` first.
- `checkApiToken` *(optional)* — `async (raw) => tokenRecord` for Bearer PAT auth (proxy only). Wrapped as `Auth.checkApiToken`, collapsing every failure to a generic `401 LoginFailed` (no leak of existence / wrong secret / expired). Omit for apps without PATs.

Returns `{ Token, AuthToken, OidcState, Auth, router, oidc, safeInternalPath, bootstrapLocalAdmin }`.

### Pure utils (also exported from the package root)

`oidc.randomToken(bytes=32)`, `oidc.codeChallengeS256(verifier)`, `oidc.createAuthRequest()`, `oidc.buildAuthUrl(state, codeChallenge, redirectUri?)`, `oidc.exchangeCode(code, codeVerifier, redirectUri?)`, `oidc.fetchUserInfo(accessToken)`, `oidc.claimsToIdentity(claims)` — all read `conf.oidc` via `@simpleworkjs/conf`.

Discovery and ID-token verification:

- `oidc.discover({force?})` — fetch and cache the provider's discovery document. Called automatically at startup when `conf.oidc.issuer` is set, and lazily by anything that needs an endpoint.
- `oidc.endpoints()` — the endpoints in force: explicitly configured values first, discovered ones second. Synchronous.
- `oidc.verifyIdToken(idToken, {audience?, issuer?, clockToleranceSec?})` — verify signature against the provider's JWKS, then `iss`, `aud`, `exp`, `nbf`. Throws on anything it cannot positively verify.
- `oidc.verifyIdTokenIfPossible(idToken)` — the same, but returns `null` (with a one-time warning) when the provider publishes no JWKS. This is what the callback route uses.
- `oidc.canVerifyIdTokens()` — whether a JWKS is known.

`safeInternalPath(path)` — constrain a post-login redirect to a same-origin `/path`.

### `bootstrapLocalAdmin(User, { defaultName })`

Idempotently ensures `conf.auth.adminUsers[0]` (fallback `defaultName`) exists as a redis-backed local user. Password from `conf.auth.localAdminPass`, else a random one printed once. Fire-and-forget.

## Configuration

Client config comes from `conf.oidc` (deep-merged by `@simpleworkjs/conf`): `enabled`, `clientId`, `clientSecret`, `redirectUri`, `scopes`, `usernameClaim`, `groupsClaim`. The anti-lockout admin reads `conf.auth.adminUsers` / `conf.auth.localAdminPass`.

### Endpoints: set `issuer`, or set them individually

```js
oidc: {
  issuer: 'https://sso.example.com',   // everything else is discovered
  clientId: '…',
  clientSecret: '…',                   // from secrets.js
  redirectUri: 'https://app.example.com/api/auth/oidc/callback',
}
```

With `issuer` set, `authorizationEndpoint`, `tokenEndpoint`, `userinfoEndpoint`,
`jwksUri`, `revocationEndpoint` and `endSessionEndpoint` are read from the
provider's `/.well-known/openid-configuration`. Any of them may still be set
explicitly, and an explicit value always wins — so an existing deployment that
lists its endpoints by hand keeps working exactly as before.

**Setting `issuer` is also what turns on ID-token verification.** Without a
`jwksUri` there is nothing to verify against, so identity comes from the userinfo
endpoint alone (the behaviour this client has always had) and a one-time warning
is logged. With one, the callback verifies the ID token's signature, issuer,
audience and expiry, and checks that its subject matches the one userinfo
reports.

## License

MIT © William Mantly