'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { safeInternalPath } = require('../lib/safe_redirect');

test('plain /path passes through', () => {
	assert.equal(safeInternalPath('/dashboard'), '/dashboard');
});

test('root passes', () => {
	assert.equal(safeInternalPath('/'), '/');
});

test('nested path passes', () => {
	assert.equal(safeInternalPath('/a/b/c'), '/a/b/c');
});

test('relative path falls back to /', () => {
	assert.equal(safeInternalPath('dashboard'), '/');
});

test('protocol-relative //host falls back to /', () => {
	assert.equal(safeInternalPath('//evil.com'), '/');
});

test('backslash-relative /\\\\host falls back to /', () => {
	assert.equal(safeInternalPath('/\\evil.com'), '/');
});

test('absolute url falls back to /', () => {
	assert.equal(safeInternalPath('https://evil.com'), '/');
});

test('non-string falls back to /', () => {
	assert.equal(safeInternalPath(undefined), '/');
	assert.equal(safeInternalPath(null), '/');
	assert.equal(safeInternalPath(42), '/');
});