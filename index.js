'use strict';

/**
 * @simpleworkjs/oidc-client
 *
 * The shared OpenID Connect (authorization-code + PKCE) client used by the
 * theta42 operational apps (proxy, jump-host). Both apps carried byte-identical
 * copies of the OIDC handshake, the short-lived state store, the session token
 * models, the local-login/OIDC-session Auth service, the auth router, the
 * safe-redirect helper, and the anti-lockout local-admin bootstrap. This package
 * is that code, extracted once.
 *
 * It is deliberately a *factory*, not a load-and-go module: the session models
 * extend the consuming app's model-redis `Table` (so they share that app's redis
 * connection + key prefix + model registry), and `Auth` binds to that app's
 * `User` model. The app supplies its `Table` (from `setUpTable(conf.redis)`)
 * with `User` already registered; the factory creates the rest and hands back
 * the classes, the `Auth` service, the Express router, the pure oidc utils, and
 * the local-admin bootstrap helper.
 *
 * What stays app-local: the `middleware/auth.js` that turns a session/PAT into
 * `req.token`/`req.user` (it differs per app — proxy has Bearer PATs + admin
 * gating, jump-host has admin gating only), and proxy's per-host
 * `routes/host_auth.js` (which consumes the exported pure `oidc` utils).
 */

const conf = require('@simpleworkjs/conf');
const oidc = require('./lib/oidc');
const { safeInternalPath } = require('./lib/safe_redirect');
const { bootstrapLocalAdmin } = require('./lib/bootstrap');

/**
 * Wire the shared OIDC client onto an app's model layer.
 *
 * @param {object} opts
 * @param {Function} opts.Table       - the app's model-redis Table base class
 *                                      (from setUpTable). `User` MUST be
 *                                      registered on `Table.models` first.
 * @param {Function} [opts.checkApiToken] - optional async `(raw) => ApiToken`
 *                                      for Bearer PAT auth (proxy only). When
 *                                      provided it is wrapped as
 *                                      `Auth.checkApiToken`, collapsing every
 *                                      failure to a generic 401 (no leak of
 *                                      existence / wrong secret / expired).
 *                                      Omit for apps without PATs (jump-host).
 * @returns {{Token, AuthToken, OidcState, Auth, router, oidc, safeInternalPath, bootstrapLocalAdmin}}
 */
function createOidcClient({ Table, checkApiToken } = {}) {
	if (!Table) throw new Error('createOidcClient: Table is required');
	const User = Table.models && Table.models.User;
	if (!User) {
		throw new Error('createOidcClient: User must be registered on Table.models before calling');
	}

	// Start discovery now if an issuer is configured, so the first login does not
	// pay for it and a misconfigured issuer is a startup warning rather than a
	// failed login. Non-blocking and non-fatal: every path that needs an endpoint
	// retries discovery lazily, so this is a warm-up, not a prerequisite.
	if(conf.oidc && conf.oidc.issuer){
		oidc.discover().catch((error) => {
			console.warn(`[oidc-client] OIDC discovery for "${conf.oidc.issuer}" failed at startup: `
				+ `${error.message} (it will be retried on first use)`);
		});
	}

	const { Token, AuthToken } = require('./lib/token')(Table);
	const { OidcState } = require('./lib/oidc_state')(Table);
	const { Auth } = require('./lib/auth')({ User, AuthToken, checkApiToken });
	const router = require('./lib/router')({ Auth, OidcState, oidc, safeInternalPath });

	return { Token, AuthToken, OidcState, Auth, router, oidc, safeInternalPath, bootstrapLocalAdmin };
}

module.exports = { createOidcClient, oidc, safeInternalPath, bootstrapLocalAdmin };