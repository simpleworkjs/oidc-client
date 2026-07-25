'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const oidc = require('../lib/oidc');

test('randomToken returns base64url with no padding and is unique', () => {
	const t = oidc.randomToken();
	assert.ok(typeof t === 'string' && t.length > 0);
	assert.ok(/^[A-Za-z0-9_-]+$/.test(t), 'base64url charset only');
	assert.ok(!t.includes('='), 'no padding');
	assert.notEqual(oidc.randomToken(), oidc.randomToken(), 'unique across calls');
});

test('codeChallengeS256 equals Node canonical base64url(SHA256(verifier))', () => {
	const verifier = 'a-test-pkce-verifier-value-1234567890';
	const expected = crypto.createHash('sha256').update(verifier).digest('base64url');
	assert.equal(oidc.codeChallengeS256(verifier), expected);
	const out = oidc.codeChallengeS256(verifier);
	assert.ok(!out.includes('=') && !/[+/]/.test(out), 'no base64-standard chars');
});

test('createAuthRequest returns a bound state/verifier/challenge triple', () => {
	const r = oidc.createAuthRequest();
	assert.ok(r.state && r.codeVerifier && r.codeChallenge);
	assert.equal(r.codeChallenge, oidc.codeChallengeS256(r.codeVerifier));
	assert.notEqual(r.state, r.codeVerifier);
});

test('buildAuthUrl assembles the authorize URL with PKCE params from conf.oidc', () => {
	const url = new URL(oidc.buildAuthUrl('st', 'ch'));
	assert.equal(url.pathname, '/oauth/authorize');
	assert.equal(url.searchParams.get('response_type'), 'code');
	assert.equal(url.searchParams.get('client_id'), 'test-client');
	assert.equal(url.searchParams.get('redirect_uri'), 'https://app.example.com/api/auth/oidc/callback');
	assert.equal(url.searchParams.get('state'), 'st');
	assert.equal(url.searchParams.get('code_challenge'), 'ch');
	assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
	assert.equal(url.searchParams.get('scope'), 'openid profile email groups');
});

test('buildAuthUrl honors a per-host redirectUri override', () => {
	const url = new URL(oidc.buildAuthUrl('st', 'ch', 'https://host.example.com/__proxy_auth/callback'));
	assert.equal(url.searchParams.get('redirect_uri'), 'https://host.example.com/__proxy_auth/callback');
});

test('claimsToIdentity pulls username + groups, coercing a single group string', () => {
	const id = oidc.claimsToIdentity({ preferred_username: 'alice', groups: ['g1', 'g2'] });
	assert.equal(id.username, 'alice');
	assert.deepEqual(id.groups, ['g1', 'g2']);

	const id2 = oidc.claimsToIdentity({ sub: 'bob', groups: 'admins' });
	assert.equal(id2.username, 'bob');
	assert.deepEqual(id2.groups, ['admins']);

	const id3 = oidc.claimsToIdentity({ preferred_username: 'carol' });
	assert.deepEqual(id3.groups, []);
});