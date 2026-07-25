'use strict';

const conf = require('@simpleworkjs/conf');
const crypto = require('crypto');

/**
 * Anti-lockout local admin bootstrap.
 *
 * Idempotently ensures the first entry of `conf.auth.adminUsers` exists as a
 * redis-backed local user, so an operator can always log in even if the SSO/OIDC
 * is unreachable (the whole point of "OIDC + internal users"). The account name
 * honors the operator's `adminUsers[0]` (so it matches the permission bootstrap
 * migration), falling back to `defaultName` only when adminUsers is unset.
 *
 * `defaultPass` comes from `conf.auth.localAdminPass` (an orchestrator — e.g.
 * theta-env's setup.sh — can set it in the secrets file to make this
 * deterministic). If unset, a random password is generated and printed once.
 * Only used on first creation; once the account exists this never reads it.
 *
 * Fire-and-forget by design (mirrors the original IIFE in user_redis.js); any
 * unexpected rejection is swallowed so it can never crash app startup.
 *
 * @param {Function} User - the app's registered User model (Table.models.User)
 * @param {object} [opts]
 * @param {string} [opts.defaultName] - fallback admin name when adminUsers is unset
 *                                       (proxy: 'proxyadmin2', jump-host: 'jumpadmin')
 */
function bootstrapLocalAdmin(User, { defaultName } = {}){
	(async function(){
		var defaultUser = (conf.auth && conf.auth.adminUsers && conf.auth.adminUsers[0]) || defaultName;
		var defaultPass = (conf.auth && conf.auth.localAdminPass);
		if (!defaultPass) {
			defaultPass = crypto.randomBytes(16).toString('hex');
			console.warn(`====================================================================`);
			console.warn(`Bootstrap admin "${defaultUser}" created with random password:`);
			console.warn(`${defaultPass}`);
			console.warn(`Set auth.localAdminPass in your secrets file to make this deterministic.`);
			console.warn(`====================================================================`);
		}
		try{
			let user = await User.get(defaultUser);
		}catch(error){
			try{
				let user = await User.create({
					username:defaultUser,
					password: defaultPass,
					created_by: defaultUser
				});
				console.log(defaultUser, 'created');
			}catch(error){
				console.error(error)
			}
		}
	})().catch(()=>{});
}

module.exports = { bootstrapLocalAdmin };