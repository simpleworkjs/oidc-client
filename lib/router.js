'use strict';

const { Router } = require('express');
const { rateLimit } = require('express-rate-limit');
const conf = require('@simpleworkjs/conf');

/**
 * The auth router: POST /login, ALL /logout, GET /oidc/start, GET /oidc/callback.
 *
 * Factory form: receives the `Auth` service, the `OidcState` store, the pure
 * `oidc` utils, and `safeInternalPath` from createOidcClient. A fresh Router is
 * built per call so two apps in one process don't share route state.
 */
module.exports = function({ Auth, OidcState, oidc, safeInternalPath }){
	const router = Router();

	// Throttle unauthenticated auth endpoints (credential login + the OIDC
	// handshake) to blunt brute-force / callback abuse. Keyed per IP.
	const authLimiter = rateLimit({
		windowMs: 15 * 60 * 1000,   // 15 minutes
		max: 60,                    // 60 attempts per IP per window
		standardHeaders: true,
		legacyHeaders: false,
		message: {name: 'TooManyRequests', message: 'Too many attempts, please try again later.'},
	});


	router.post('/login', authLimiter, async function(req, res, next){
		try{
			let auth = await Auth.login(req.body);
			return res.json({
				login: true,
				token: auth.token.token,
				message:`${req.body.username} logged in!`,
			});
		}catch(error){
			next(error);
		}
	});

	router.all('/logout', async function(req, res, next){
		try{
			if(req.user){
				await req.user.logout();
			}

			res.json({message: 'Bye'})
		}catch(error){
			next(error);
		}
	});

	/**
	 * OIDC login start: create a PKCE + state challenge, persist it (auto-expiring
	 * via OidcState TTL), and redirect the browser to the SSO authorize endpoint.
	 */
	router.get('/oidc/start', authLimiter, async function(req, res, next){
		try{
			if(!conf.oidc || !conf.oidc.enabled){
				let error = new Error('OidcDisabled');
				error.status = 404;
				error.message = 'OIDC login is not enabled.';
				throw error;
			}

			let {state, codeVerifier, codeChallenge} = oidc.createAuthRequest();
			await OidcState.create({
				state,
				codeVerifier,
				// Sanitize now so a hostile ?redirect= can't be stored and later
				// reflected into the login page's navigation.
				redirect: safeInternalPath(req.query.redirect || '/'),
			});

			return res.redirect(oidc.buildAuthUrl(state, codeChallenge));
		}catch(error){
			next(error);
		}
	});

	/**
	 * OIDC callback: validate state (consuming the one-time record), exchange the
	 * code for tokens, read identity from userinfo, establish a session, and hand
	 * the app token back to the browser via a URL fragment for the login page to
	 * store in localStorage.
	 */
	router.get('/oidc/callback', authLimiter, async function(req, res, next){
		try{
			let {code, state} = req.query;
			if(!code || !state){
				let error = new Error('OidcCallbackInvalid');
				error.status = 400;
				error.message = 'Missing code or state.';
				throw error;
			}

			// get() throws if the state is unknown or has expired — this both binds
			// the callback to our request and bounds replay.
			let saved = await OidcState.get(state);
			await saved.remove();

			let tokens = await oidc.exchangeCode(code, saved.codeVerifier);

			// Verify the ID token when the provider publishes a JWKS. Userinfo
			// alone is a sound way to read identity -- the access token is
			// exchanged server-side over TLS -- but it establishes nothing about
			// WHO asserted it. The ID token, verified, says the assertion came
			// from the configured issuer and was minted for this client.
			let verified = await oidc.verifyIdTokenIfPossible(tokens.id_token);

			let claims = await oidc.fetchUserInfo(tokens.access_token);

			// The identity we act on has to be the one that was signed for. Both
			// halves come from the same provider over TLS, so a mismatch is not
			// an expected condition -- but acting on an unverified `sub` when a
			// verified one is right there is the kind of gap that only shows up
			// after it has been used.
			if(verified && verified.sub && claims.sub && verified.sub !== claims.sub){
				let error = new Error('OidcSubjectMismatch');
				error.name = 'OidcSubjectMismatch';
				error.status = 401;
				error.message = 'The ID token and userinfo describe different subjects.';
				throw error;
			}

			let identity = oidc.claimsToIdentity(claims);

			let {token} = await Auth.oidcSession(identity);

			let redirect = safeInternalPath(saved.redirect || '/');
			return res.redirect(
				`/login#token=${encodeURIComponent(token.token)}&redirect=${encodeURIComponent(redirect)}`
			);
		}catch(error){
			next(error);
		}
	});

	return router;
};