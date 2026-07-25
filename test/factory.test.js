'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { createOidcClient } = require('..');

// Minimal stand-in for a model-redis Table: a shared `models` registry populated
// by `register(Model)` keyed on the class name (matching model-redis's real
// `static register = function(Model){ this.models[Model.name] = Model; }`).
function makeTable(){
	const models = {};
	function Table(){}
	Table.models = models;
	// Matches model-redis: `Model = Model || this` so `Class.register()` (no
	// arg) registers the class itself under its literal name.
	Table.register = function(M){ M = M || this; this.models[M.name] = M; };
	return Table;
}

function makeUser(Table){
	class User extends Table { static _key = 'username'; }
	User.register();
	return User;
}

test('createOidcClient throws without Table', () => {
	assert.throws(() => createOidcClient({}), /Table is required/);
});

test('createOidcClient throws when User is not registered on Table.models', () => {
	const Table = makeTable();
	assert.throws(() => createOidcClient({ Table }), /User must be registered/);
});

test('createOidcClient returns the full shared client surface', () => {
	const Table = makeTable();
	makeUser(Table);
	const c = createOidcClient({ Table });
	for (const k of ['Token', 'AuthToken', 'OidcState', 'Auth', 'router', 'oidc', 'safeInternalPath', 'bootstrapLocalAdmin']) {
		assert.ok(c[k] !== undefined, `expected ${k} on the client surface`);
	}
	// Classes are registered on the app's Table under their literal names.
	assert.equal(Table.models.Token, c.Token);
	assert.equal(Table.models.AuthToken, c.AuthToken);
	assert.equal(Table.models.OidcState, c.OidcState);
	// Auth binds the app's User + the freshly-created AuthToken.
	assert.equal(typeof c.Auth.login, 'function');
	assert.equal(typeof c.Auth.oidcSession, 'function');
	assert.equal(typeof c.Auth.checkToken, 'function');
	assert.equal(typeof c.Auth.logout, 'function');
	// router is an Express router (a function with .stack).
	assert.equal(typeof c.router, 'function');
	assert.ok(Array.isArray(c.router.stack));
});

test('checkApiToken is absent when not provided (jump-host shape)', () => {
	const Table = makeTable();
	makeUser(Table);
	const c = createOidcClient({ Table });
	assert.equal(c.Auth.checkApiToken, undefined);
});

test('checkApiToken collapses every failure to a generic 401 (proxy shape)', async () => {
	const Table = makeTable();
	makeUser(Table);
	let calls = 0;
	const c = createOidcClient({
		Table,
		checkApiToken: async (raw) => { calls++; throw new Error('wrong secret details that must not leak'); },
	});
	assert.equal(typeof c.Auth.checkApiToken, 'function');
	await assert.rejects(
		() => c.Auth.checkApiToken('prx_1_2'),
		(err) => err.name === 'LoginFailed' && err.status === 401 && !/wrong secret details/.test(err.message),
	);
	assert.equal(calls, 1, 'the underlying authenticator was invoked exactly once');
});

test('checkApiToken passes a successful authentication through unchanged', async () => {
	const Table = makeTable();
	makeUser(Table);
	const c = createOidcClient({ Table, checkApiToken: async (raw) => ({ id: raw, groups: ['g'] }) });
	const out = await c.Auth.checkApiToken('prx_3_4');
	assert.deepEqual(out, { id: 'prx_3_4', groups: ['g'] });
});