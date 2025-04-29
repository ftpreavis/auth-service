<<<<<<< HEAD
import Fastify from 'fastify';
import axios from 'axios';
import fastifyOauth2 from '@fastify/oauth2';
import dotenv from 'dotenv';
=======
const Fastify = require('fastify');
const axios = require('axios');
const metrics = require('fastify-metrics');
>>>>>>> dd8c26e (- | removed google auth)


const fastify = Fastify({ logger: true });

<<<<<<< HEAD
// Enregistrer le plugin OAuth2
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
}).ready((err) => {
	if (err) {
		console.error('OAuth2 Plugin registration failed:', err);
		process.exit(1);
	} else {
		console.log('OAuth2 Plugin registered successfully');
	}
});

// Route de callback OAuth2
fastify.get('/auth/google/callback', async (request, reply) => {
	try {
		const token = await fastify.googleOAuth2.getAccessTokenFromAuthorizationCodeFlow(request);

		// Vérifier que le token est bien défini avant de procéder
		if (!token.token.access_token) {
			return reply.code(400).send({ error: 'Access token is missing' });
		}

		const userInfo = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
			headers: {
				Authorization: `Bearer ${token.token.access_token}`,
			},
		});

		reply.send(userInfo.data);
	} catch (err) {
		fastify.log.error(err);

		// Gestion spécifique de l'erreur Axios
		if (err.response) {
			// Si l'erreur vient de la requête axios (par exemple, 401 ou 403)
			reply.code(err.response.status).send({
				error: 'OAuth callback failed',
				details: err.response.data,
			});
		} else {
			reply.code(500).send({
				error: 'OAuth callback failed',
				details: err.message,
			});
		}
	}
});

fastify.get('/auth/logout', async (request, reply) => {
	reply.clearCookie('access_token');

	const googleLogoutUrl = 'https://accounts.google.com/Logout';
	reply.redirect(googleLogoutUrl);
});
=======
fastify.register(metrics, { endpoint: '/metrics' });
fastify.register(require('@fastify/cookie'));
>>>>>>> dd8c26e (- | removed google auth)

// Démarrer le serveur
fastify.listen({ port: 3000, host: '0.0.0.0' }, (err, address) => {
	if (err) {
		fastify.log.error(err);
		process.exit(1);
	}
	fastify.log.info(`Server listening at ${address}`);
});
