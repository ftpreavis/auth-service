// index.js
const Fastify = require('fastify');
const axios = require('axios');
const fastifyOauth2 = require('@fastify/oauth2');
const metrics = require('fastify-metrics');
const dotenv = require('dotenv');

dotenv.config();

const fastify = Fastify({ logger: true });

fastify.register(metrics, { endpoint: '/metrics' });

fastify.register(fastifyOauth2, {
	name: 'googleOAuth2',
	scope: ['profile', 'email'],
	credentials: {
		client: {
			id: process.env.GOOGLE_CLIENT_ID,
			secret: process.env.GOOGLE_CLIENT_SECRET,
		},
		auth: fastifyOauth2.GOOGLE_CONFIGURATION,
	},
	startRedirectPath: '/auth/google',
	callbackUri: 'http://localhost:4001/auth/google/callback',
}).ready(err => {
	if (err) {
		console.error('OAuth2 Plugin registration failed:', err);
		process.exit(1);
	}
	console.log('OAuth2 Plugin registered successfully');
});

fastify.get('/auth/google/callback', async (request, reply) => {
	try {
		const token = await fastify.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

		if (!token.token.access_token) {
			return reply.code(400).send({ error: 'Access token is missing' });
		}

		const userInfo = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
			headers: { Authorization: `Bearer ${token.token.access_token}` }
		});

		reply.send(userInfo.data);
	} catch (err) {
		fastify.log.error(err);
		if (err.response) {
			reply
				.code(err.response.status)
				.send({ error: 'OAuth callback failed', details: err.response.data });
		} else {
			reply
				.code(500)
				.send({ error: 'OAuth callback failed', details: err.message });
		}
	}
});

fastify.get('/auth/logout', async (request, reply) => {
	reply.clearCookie('access_token');
	reply.redirect('https://accounts.google.com/Logout');
});

fastify.listen({ port: 3000, host: '0.0.0.0' }, (err, address) => {
	if (err) {
		fastify.log.error(err);
		process.exit(1);
	}
	fastify.log.info(`Server listening at ${address}`);
});
