'use strict';

const crypto = require('crypto');
const conf = require('@simpleworkjs/conf');

/**
 * Minimal OpenID Connect authorization-code + PKCE client.
 *
 * Identity is read from the userinfo endpoint (the access token is exchanged
 * server-side over TLS). When the provider publishes a `jwks_uri`, the ID token
 * is ALSO verified and its subject cross-checked against userinfo — see
 * verifyIdToken below. Uses Node's global fetch (Node 18+) and crypto — no
 * external dependency.
 *
 * Endpoints come from `conf.oidc.issuer` via OpenID Connect Discovery, or may
 * be set individually (authorizationEndpoint / tokenEndpoint / userinfoEndpoint
 * / jwksUri), which always wins over what discovery returns. Client config comes
 * from conf.oidc (+ clientSecret from secrets.js, deep-merged by
 * @simpleworkjs/conf).
 */

const base64url = buf => buf.toString('base64')
	.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

// How long a fetched discovery document / key set is trusted before being
// re-read. Both are effectively static; this only bounds how long a rotated key
// takes to be picked up, and an unknown `kid` forces a refresh immediately
// regardless (see jwkFor).
const CACHE_TTL_MS = 60 * 60 * 1000;

function oidcError(name, message, status = 502){
	let error = new Error(name);
	error.name = name;
	error.message = message;
	error.status = status;
	return error;
}

// A high-entropy random string for `state` / PKCE verifier.
function randomToken(bytes = 32){
	return base64url(crypto.randomBytes(bytes));
}

// PKCE S256 challenge derived from the verifier.
function codeChallengeS256(verifier){
	return base64url(crypto.createHash('sha256').update(verifier).digest());
}

// ── Discovery ───────────────────────────────────────────────────────────────
//
// Configuring four endpoint URLs by hand is four chances to get one subtly
// wrong, and a provider that moves one has no way to tell you. Set
// `conf.oidc.issuer` and they are read from the provider's own discovery
// document instead. Individually configured endpoints still win, so an existing
// deployment that lists them explicitly is unaffected.

let discoveryCache = null;      // { fetchedAt, doc }
let discoveryInFlight = null;

// Fetch (and cache) the provider's discovery document. Idempotent, and safe to
// call concurrently -- overlapping callers share one request rather than each
// issuing their own.
async function discover({ force = false } = {}){
	let issuer = conf.oidc && conf.oidc.issuer;
	if(!issuer) return null;

	if(!force && discoveryCache && (Date.now() - discoveryCache.fetchedAt) < CACHE_TTL_MS){
		return discoveryCache.doc;
	}
	if(discoveryInFlight) return discoveryInFlight;

	let url = `${String(issuer).replace(/\/+$/, '')}/.well-known/openid-configuration`;
	discoveryInFlight = (async () => {
		let res = await fetch(url, {headers: {Accept: 'application/json'}});
		if(!res.ok){
			throw oidcError('OidcDiscoveryFailed', `Discovery request to ${url} failed (${res.status}).`);
		}
		let doc = await res.json();
		// The issuer in the document must match the one we asked, or we are
		// being told about a different provider than the one configured
		// (OpenID Connect Discovery 1.0 §4.3).
		if(doc.issuer && String(doc.issuer).replace(/\/+$/, '') !== String(issuer).replace(/\/+$/, '')){
			throw oidcError('OidcDiscoveryIssuerMismatch',
				`Discovery document at ${url} advertises issuer "${doc.issuer}", expected "${issuer}".`);
		}
		discoveryCache = {fetchedAt: Date.now(), doc};
		return doc;
	})();

	try{
		return await discoveryInFlight;
	}finally{
		discoveryInFlight = null;
	}
}

// The endpoints in force right now: explicit conf first, discovery second.
// Synchronous on purpose -- buildAuthUrl and friends are called per request and
// were synchronous before discovery existed. `discover()` populates the cache at
// startup (index.js) and is retried lazily by the async paths below.
function endpoints(){
	let o = conf.oidc || {};
	let d = (discoveryCache && discoveryCache.doc) || {};
	return {
		issuer: o.issuer || d.issuer,
		authorizationEndpoint: o.authorizationEndpoint || d.authorization_endpoint,
		tokenEndpoint: o.tokenEndpoint || d.token_endpoint,
		userinfoEndpoint: o.userinfoEndpoint || d.userinfo_endpoint,
		jwksUri: o.jwksUri || d.jwks_uri,
		revocationEndpoint: o.revocationEndpoint || d.revocation_endpoint,
		endSessionEndpoint: o.endSessionEndpoint || d.end_session_endpoint,
	};
}

// Resolve one endpoint, running discovery first if it has not happened yet.
// This is what makes `issuer`-only configuration work without the caller having
// to sequence a startup step.
async function requireEndpoint(name){
	let found = endpoints()[name];
	if(found) return found;

	if(conf.oidc && conf.oidc.issuer){
		await discover();
		found = endpoints()[name];
		if(found) return found;
	}

	throw oidcError('OidcEndpointMissing',
		`No ${name} configured. Set conf.oidc.issuer to discover it, or conf.oidc.${name} explicitly.`,
		500);
}

// Generate the {state, codeVerifier, codeChallenge} triple for a new login.
function createAuthRequest(){
	let state = randomToken(32);
	let codeVerifier = randomToken(32);
	let codeChallenge = codeChallengeS256(codeVerifier);
	return {state, codeVerifier, codeChallenge};
}

// Build the SSO authorize URL the browser is redirected to. `redirectUri`
// overrides conf.oidc.redirectUri (per-host SSO uses a per-host callback).
function buildAuthUrl(state, codeChallenge, redirectUri){
	let o = conf.oidc;
	let authorizationEndpoint = endpoints().authorizationEndpoint;
	if(!authorizationEndpoint){
		// Synchronous by contract (it builds a redirect URL mid-request), so it
		// cannot run discovery itself. index.js kicks discovery off at startup;
		// this is what an app that set neither the issuer nor the endpoint sees.
		throw oidcError('OidcEndpointMissing',
			'No authorizationEndpoint configured. Set conf.oidc.issuer to discover it, '
			+ 'or conf.oidc.authorizationEndpoint explicitly.', 500);
	}
	let params = new URLSearchParams({
		response_type: 'code',
		client_id: o.clientId,
		redirect_uri: redirectUri || o.redirectUri,
		scope: (o.scopes || ['openid', 'profile', 'email', 'groups']).join(' '),
		state,
		code_challenge: codeChallenge,
		code_challenge_method: 'S256',
	});
	return `${authorizationEndpoint}?${params.toString()}`;
}

// Exchange an authorization code for tokens at the token endpoint. `redirectUri`
// must match the one used in buildAuthUrl (per-host for per-host SSO).
async function exchangeCode(code, codeVerifier, redirectUri){
	let o = conf.oidc;
	let body = new URLSearchParams({
		grant_type: 'authorization_code',
		code,
		redirect_uri: redirectUri || o.redirectUri,
		client_id: o.clientId,
		client_secret: o.clientSecret,
		code_verifier: codeVerifier,
	});

	let res = await fetch(await requireEndpoint('tokenEndpoint'), {
		method: 'POST',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded',
			'Accept': 'application/json',
		},
		body: body.toString(),
	});

	if(!res.ok){
		let text = await res.text().catch(() => '');
		let error = new Error('OidcTokenExchangeFailed');
		error.name = 'OidcTokenExchangeFailed';
		error.message = `Token exchange failed (${res.status}): ${text}`;
		error.status = 502;
		throw error;
	}

	return res.json();
}

// Fetch the userinfo claims for an access token.
async function fetchUserInfo(accessToken){
	let res = await fetch(await requireEndpoint('userinfoEndpoint'), {
		headers: {
			'Authorization': `Bearer ${accessToken}`,
			'Accept': 'application/json',
		},
	});

	if(!res.ok){
		let error = new Error('OidcUserInfoFailed');
		error.name = 'OidcUserInfoFailed';
		error.message = `Userinfo request failed (${res.status})`;
		error.status = 502;
		throw error;
	}

	return res.json();
}

// ── ID token verification ───────────────────────────────────────────────────
//
// The flow reads identity from userinfo, which is sound on its own -- the access
// token is exchanged server-side over TLS. Verifying the ID token as well binds
// that identity to something the provider SIGNED: it proves the assertion came
// from the configured issuer, was minted for THIS client, and has not expired,
// none of which a userinfo response on its own establishes.
//
// This was previously skipped because the SSO published no `jwks_uri` and there
// was nothing to verify against. It now does.

let jwksCache = null;       // { fetchedAt, keys: [jwk] }

// The JWS algorithms worth accepting, and how Node verifies each. `none` is
// absent deliberately: an unsigned ID token is the classic JWT forgery, and an
// algorithm we do not name here is refused rather than guessed at.
const JWS_ALGS = {
	RS256: {hash: 'sha256', opts: {}},
	RS384: {hash: 'sha384', opts: {}},
	RS512: {hash: 'sha512', opts: {}},
	PS256: {hash: 'sha256', opts: {padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST}},
	PS384: {hash: 'sha384', opts: {padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST}},
	PS512: {hash: 'sha512', opts: {padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST}},
	ES256: {hash: 'sha256', opts: {dsaEncoding: 'ieee-p1363'}},
	ES384: {hash: 'sha384', opts: {dsaEncoding: 'ieee-p1363'}},
	ES512: {hash: 'sha512', opts: {dsaEncoding: 'ieee-p1363'}},
};

async function fetchJwks({ force = false } = {}){
	if(!force && jwksCache && (Date.now() - jwksCache.fetchedAt) < CACHE_TTL_MS){
		return jwksCache.keys;
	}
	let uri = await requireEndpoint('jwksUri');
	let res = await fetch(uri, {headers: {Accept: 'application/json'}});
	if(!res.ok){
		throw oidcError('OidcJwksFailed', `JWKS request to ${uri} failed (${res.status}).`);
	}
	let doc = await res.json();
	let keys = Array.isArray(doc && doc.keys) ? doc.keys : [];
	jwksCache = {fetchedAt: Date.now(), keys};
	return keys;
}

// Find the signing key for a token header. An unknown `kid` refetches once
// before giving up, so a key rotation is picked up immediately instead of at
// the end of the cache TTL -- which would otherwise mean an hour of failed
// logins every time the provider rotates.
async function jwkFor(header){
	let match = (keys) => keys.find(k =>
		(!header.kid || k.kid === header.kid) &&
		(!k.alg || !header.alg || k.alg === header.alg) &&
		(!k.use || k.use === 'sig'));

	let found = match(await fetchJwks());
	if(found) return found;

	found = match(await fetchJwks({force: true}));
	if(found) return found;

	throw oidcError('OidcJwksKeyNotFound',
		`No signing key for kid "${header.kid || '(none)'}" in the provider's JWKS.`);
}

/**
 * Verify an ID token and return its claims.
 *
 * Checks the signature against the provider's JWKS, then `iss`, `aud`, `exp`
 * and `nbf`. Throws on anything it cannot positively verify -- a token that
 * fails any of these is not a weaker assertion, it is one that did not come
 * from where it claims.
 */
async function verifyIdToken(idToken, { audience, issuer, clockToleranceSec = 60 } = {}){
	let o = conf.oidc || {};
	let parts = String(idToken || '').split('.');
	if(parts.length !== 3){
		throw oidcError('OidcIdTokenMalformed', 'ID token is not a well-formed JWS.', 400);
	}

	let header;
	let claims;
	try{
		header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
		claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
	}catch(_){
		throw oidcError('OidcIdTokenMalformed', 'ID token header or payload is not valid JSON.', 400);
	}

	let spec = JWS_ALGS[header.alg];
	if(!spec){
		throw oidcError('OidcIdTokenAlgUnsupported',
			`ID token is signed with "${header.alg}", which is not accepted.`);
	}

	let jwk = await jwkFor(header);
	let key;
	try{
		key = crypto.createPublicKey({key: jwk, format: 'jwk'});
	}catch(error){
		throw oidcError('OidcJwksKeyInvalid', `Provider JWKS key could not be read: ${error.message}`);
	}

	let signed = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
	let signature = Buffer.from(parts[2], 'base64url');
	let ok = crypto.verify(spec.hash, signed, {key, ...spec.opts}, signature);
	if(!ok){
		throw oidcError('OidcIdTokenSignatureInvalid', 'ID token signature does not verify.', 401);
	}

	let expectedIssuer = issuer || endpoints().issuer;
	if(expectedIssuer && String(claims.iss).replace(/\/+$/, '') !== String(expectedIssuer).replace(/\/+$/, '')){
		throw oidcError('OidcIdTokenIssuerMismatch',
			`ID token issuer "${claims.iss}" is not "${expectedIssuer}".`, 401);
	}

	let expectedAudience = audience || o.clientId;
	if(expectedAudience){
		let aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
		if(!aud.includes(expectedAudience)){
			// A token minted for a different client is a valid token -- for
			// somebody else. Accepting it is how one relying party's token
			// becomes a login here.
			throw oidcError('OidcIdTokenAudienceMismatch',
				`ID token audience does not include "${expectedAudience}".`, 401);
		}
	}

	let now = Math.floor(Date.now() / 1000);
	if(typeof claims.exp === 'number' && now > claims.exp + clockToleranceSec){
		throw oidcError('OidcIdTokenExpired', 'ID token has expired.', 401);
	}
	if(typeof claims.nbf === 'number' && now + clockToleranceSec < claims.nbf){
		throw oidcError('OidcIdTokenNotYetValid', 'ID token is not yet valid.', 401);
	}

	return claims;
}

// Whether ID-token verification is possible at all: a provider that publishes no
// JWKS (and has no jwksUri configured) cannot be verified against, and the flow
// falls back to userinfo alone as it always did.
function canVerifyIdTokens(){
	return Boolean(endpoints().jwksUri);
}

let warnedNoJwks = false;
let warnedDiscoveryUnavailable = false;

/**
 * Verify an ID token when the provider gives us the means to, and say so out
 * loud when it does not.
 *
 * The decision lives here rather than at the call site so that "we skipped
 * verification" can never be an accident of ordering -- a provider with no JWKS
 * is a deliberate, logged fallback to userinfo-only identity (which is how this
 * client behaved for its whole life), while a provider that HAS one and fails
 * verification is an error, not a shrug.
 *
 * Returns the verified claims, or null when verification was not possible.
 */
async function verifyIdTokenIfPossible(idToken, options){
	if(!idToken) return null;

	// Resolve the JWKS location, running discovery if an issuer is configured.
	//
	// A discovery attempt that FAILS is not a verification failure -- it means we
	// never established that this provider can be verified against at all, which
	// is the same position as a provider that publishes no JWKS. Treating it as
	// fatal would mean an upgrade breaks every login on any deployment whose
	// issuer is set but not reachable from where this code runs: exactly the
	// theta42 proxy, which points `issuer` at the public HTTPS host while
	// deliberately reaching the SSO over an internal address for everything else.
	//
	// Configure `jwksUri` explicitly (or an issuer that resolves from here) to
	// turn verification on in that setup. Once discovery HAS produced a JWKS, a
	// later failure to use it is fatal -- that is a provider we know we should be
	// able to verify against.
	let jwksUri = endpoints().jwksUri;
	if(!jwksUri && conf.oidc && conf.oidc.issuer){
		try{
			await discover();
			jwksUri = endpoints().jwksUri;
		}catch(error){
			if(!warnedDiscoveryUnavailable){
				warnedDiscoveryUnavailable = true;
				console.warn(`[oidc-client] Could not read the discovery document at "${conf.oidc.issuer}" `
					+ `(${error.message}), so ID token signatures are not verified and identity comes from the `
					+ 'userinfo endpoint alone. Set conf.oidc.jwksUri explicitly if the issuer is not reachable '
					+ 'from this process.');
			}
			return null;
		}
	}

	if(!jwksUri){
		if(!warnedNoJwks){
			warnedNoJwks = true;
			console.warn('[oidc-client] The provider publishes no jwks_uri and none is configured, '
				+ 'so ID token signatures are not verified; identity comes from the userinfo endpoint alone. '
				+ 'Set conf.oidc.issuer (or conf.oidc.jwksUri) once the provider publishes one.');
		}
		return null;
	}

	return verifyIdToken(idToken, options);
}

// Pull the app username and group list out of userinfo claims per conf.
function claimsToIdentity(claims){
	let o = conf.oidc;
	let username = claims[o.usernameClaim || 'preferred_username'] || claims.sub;
	let groups = claims[o.groupsClaim || 'groups'] || [];
	if(!Array.isArray(groups)) groups = [groups].filter(Boolean);
	return {username, groups, claims};
}

module.exports = {
	randomToken,
	codeChallengeS256,
	createAuthRequest,
	buildAuthUrl,
	exchangeCode,
	fetchUserInfo,
	claimsToIdentity,
	discover,
	endpoints,
	verifyIdToken,
	verifyIdTokenIfPossible,
	canVerifyIdTokens,
	// Test seam: drop the discovery + JWKS caches.
	_resetCaches(){
		discoveryCache = null;
		jwksCache = null;
		discoveryInFlight = null;
		warnedNoJwks = false;
		warnedDiscoveryUnavailable = false;
	},
};