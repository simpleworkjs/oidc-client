'use strict';

// Minimal conf for unit tests. CONF_DIR=test/fixtures/conf (set in the
// package's `test` script) points @simpleworkjs/conf here so lib/oidc.js can
// load without the app's real conf/ tree. Not shipped (test/ is excluded by
// the package.json `files` list).
module.exports = {
	oidc: {
		enabled: true,
		clientId: 'test-client',
		clientSecret: 'test-secret',
		redirectUri: 'https://app.example.com/api/auth/oidc/callback',
		authorizationEndpoint: 'https://sso.example.com/oauth/authorize',
		tokenEndpoint: 'https://sso.example.com/oauth/token',
		userinfoEndpoint: 'https://sso.example.com/api/user/me',
		scopes: ['openid', 'profile', 'email', 'groups'],
		usernameClaim: 'preferred_username',
		groupsClaim: 'groups',
	},
	auth: { adminUsers: ['admin'] },
};