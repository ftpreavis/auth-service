const Fastify = require('fastify');
const axios = require('axios');
const metrics = require('fastify-metrics');


const fastify = Fastify({ logger: true });

fastify.register(metrics, { endpoint: '/metrics' });
fastify.register(require('@fastify/cookie'));

// Démarrer le serveur
fastify.listen({ port: 3000, host: '0.0.0.0' }, (err, address) => {
	if (err) {
		fastify.log.error(err);
		process.exit(1);
	}
	fastify.log.info(`Server listening at ${address}`);
});
