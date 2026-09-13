'use strict';

// Discovery + ID-token verification.
//
// Exercised against a real HTTP server serving a real discovery document and a
// real JWKS, with tokens signed by a real key — the whole value of this code is
// that it says no to a token it should say no to, and a mocked verifier would
// only prove the mock says no.

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const http = require('node:http');
const conf = require('@simpleworkjs/conf');
const oidc = require('../lib/oidc');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key-1', use: 'sig', alg: 'RS256' };

// A second key the provider does NOT publish, for forging.
const foreign = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

function signJwt(claims, { key = privateKey, kid = 'test-key-1', alg = 'RS256' } = {}) {
	const header = b64url({ alg, typ: 'JWT', kid });
	const payload = b64url(claims);
	if (alg === 'none') return `${header}.${payload}.`;
	const sig = crypto.sign('sha256', Buffer.from(`${header}.${payload}`), key);
	return `${header}.${payload}.${sig.toString('base64url')}`;
}

// A provider that can be told to rotate its key or serve a mismatched issuer.
function startProvider({ issuerOverride, keys } = {}) {
	const state = { jwksRequests: 0, keys: keys || [jwk] };
	const server = http.createServer((req, res) => {
		const base = `http://127.0.0.1:${server.address().port}`;
		res.setHeader('Content-Type', 'application/json');
		if (req.url === '/.well-known/openid-configuration') {
			return res.end(JSON.stringify({
				issuer: issuerOverride || base,
				authorization_endpoint: `${base}/oauth/authorize`,
				token_endpoint: `${base}/oauth/token`,
				userinfo_endpoint: `${base}/oauth/userinfo`,
				jwks_uri: `${base}/.well-known/jwks.json`,
			}));
		}
		if (req.url === '/.well-known/jwks.json') {
			state.jwksRequests++;
			return res.end(JSON.stringify({ keys: state.keys }));
		}
		res.statusCode = 404;
		res.end('{}');
	});
	return new Promise((resolve) => {
		server.listen(0, '127.0.0.1', () => {
			state.base = `http://127.0.0.1:${server.address().port}`;
			state.close = () => new Promise(r => server.close(r));
			resolve(state);
		});
	});
}

// Point conf at a provider for one test, then put it back — conf is a singleton
// and the rest of the suite relies on the fixture's explicit endpoints.
async function withProvider(provider, fn, confOverrides = {}) {
	const original = { ...conf.oidc };
	Object.assign(conf.oidc, {
		issuer: provider.base,
		authorizationEndpoint: undefined,
		tokenEndpoint: undefined,
		userinfoEndpoint: undefined,
		jwksUri: undefined,
		...confOverrides,
	});
	oidc._resetCaches();
	try {
		return await fn();
	} finally {
		for (const k of Object.keys(conf.oidc)) delete conf.oidc[k];
		Object.assign(conf.oidc, original);
		oidc._resetCaches();
	}
}

const validClaims = (base) => ({
	iss: base,
	sub: 'alice',
	aud: 'test-client',
	exp: Math.floor(Date.now() / 1000) + 300,
	iat: Math.floor(Date.now() / 1000),
});

test('discovery fills in the endpoints from the issuer alone', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			await oidc.discover();
			const e = oidc.endpoints();
			assert.equal(e.authorizationEndpoint, `${p.base}/oauth/authorize`);
			assert.equal(e.tokenEndpoint, `${p.base}/oauth/token`);
			assert.equal(e.jwksUri, `${p.base}/.well-known/jwks.json`);
			// ...and buildAuthUrl, which is synchronous, can use them.
			assert.ok(oidc.buildAuthUrl('st', 'ch').startsWith(`${p.base}/oauth/authorize?`));
		});
	} finally { await p.close(); }
});

test('an explicitly configured endpoint still wins over discovery', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			await oidc.discover();
			assert.equal(oidc.endpoints().tokenEndpoint, 'https://explicit.example.com/token');
		}, { tokenEndpoint: 'https://explicit.example.com/token' });
	} finally { await p.close(); }
});

test('a discovery document advertising a different issuer is refused', async () => {
	// Otherwise the document could redirect us to someone else's endpoints.
	const p = await startProvider({ issuerOverride: 'https://not-who-we-asked.example.com' });
	try {
		await withProvider(p, async () => {
			await assert.rejects(() => oidc.discover(), /OidcDiscoveryIssuerMismatch/);
		});
	} finally { await p.close(); }
});

test('a correctly signed ID token verifies and returns its claims', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			const claims = await oidc.verifyIdToken(signJwt(validClaims(p.base)));
			assert.equal(claims.sub, 'alice');
		});
	} finally { await p.close(); }
});

test('a token signed by a key the provider does not publish is refused', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			const forged = signJwt(validClaims(p.base), { key: foreign.privateKey });
			await assert.rejects(() => oidc.verifyIdToken(forged), /OidcIdTokenSignatureInvalid/);
		});
	} finally { await p.close(); }
});

test('alg:none is refused rather than treated as unsigned-but-fine', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			const unsigned = signJwt(validClaims(p.base), { alg: 'none' });
			await assert.rejects(() => oidc.verifyIdToken(unsigned), /OidcIdTokenAlgUnsupported/);
		});
	} finally { await p.close(); }
});

test('a token minted for another client is refused', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			const other = signJwt({ ...validClaims(p.base), aud: 'someone-elses-client' });
			await assert.rejects(() => oidc.verifyIdToken(other), /OidcIdTokenAudienceMismatch/);
		});
	} finally { await p.close(); }
});

test('an expired token is refused, and clock tolerance is bounded', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			const stale = signJwt({ ...validClaims(p.base), exp: Math.floor(Date.now() / 1000) - 600 });
			await assert.rejects(() => oidc.verifyIdToken(stale), /OidcIdTokenExpired/);

			// Just inside the default 60s tolerance: still accepted, so a small
			// clock skew between provider and app is not a login outage.
			const justExpired = signJwt({ ...validClaims(p.base), exp: Math.floor(Date.now() / 1000) - 10 });
			assert.equal((await oidc.verifyIdToken(justExpired)).sub, 'alice');
		});
	} finally { await p.close(); }
});

test('a token from a different issuer is refused', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			const elsewhere = signJwt({ ...validClaims(p.base), iss: 'https://evil.example.com' });
			await assert.rejects(() => oidc.verifyIdToken(elsewhere), /OidcIdTokenIssuerMismatch/);
		});
	} finally { await p.close(); }
});

test('an unknown kid refetches the JWKS, so a key rotation is picked up at once', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			// Prime the cache with the original key set.
			await oidc.verifyIdToken(signJwt(validClaims(p.base)));
			const before = p.jwksRequests;

			// The provider rotates; the new token carries a kid we have not seen.
			const rotated = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
			p.keys = [{ ...rotated.publicKey.export({ format: 'jwk' }), kid: 'test-key-2', use: 'sig', alg: 'RS256' }];

			const claims = await oidc.verifyIdToken(
				signJwt(validClaims(p.base), { key: rotated.privateKey, kid: 'test-key-2' })
			);
			assert.equal(claims.sub, 'alice');
			assert.ok(p.jwksRequests > before, 'should have refetched the key set');
		});
	} finally { await p.close(); }
});

test('verifyIdTokenIfPossible skips, rather than fails, when the provider publishes no JWKS', async () => {
	// The behaviour this client had for its whole life, kept for a provider that
	// still publishes nothing to verify against.
	oidc._resetCaches();
	assert.equal(oidc.canVerifyIdTokens(), false, 'fixture conf has no jwksUri');
	assert.equal(await oidc.verifyIdTokenIfPossible('any.token.here'), null);
});

test('verifyIdTokenIfPossible verifies when the provider does publish one', async () => {
	const p = await startProvider();
	try {
		await withProvider(p, async () => {
			await oidc.discover();
			assert.equal(oidc.canVerifyIdTokens(), true);
			const claims = await oidc.verifyIdTokenIfPossible(signJwt(validClaims(p.base)));
			assert.equal(claims.sub, 'alice');
			// And a bad one is an error, not a skip.
			await assert.rejects(
				() => oidc.verifyIdTokenIfPossible(signJwt(validClaims(p.base), { key: foreign.privateKey })),
				/OidcIdTokenSignatureInvalid/
			);
		});
	} finally { await p.close(); }
});

test('a malformed token is rejected without reaching the network', async () => {
	await assert.rejects(() => oidc.verifyIdToken('not-a-jwt'), /OidcIdTokenMalformed/);
	await assert.rejects(() => oidc.verifyIdToken('a.b.c'), /OidcIdTokenMalformed/);
});
