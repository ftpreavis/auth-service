const fastify = require('fastify')();
const metrics = require('fastify-metrics');
const { getVaultValue } = require('./middleware/vault-client');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const fastifyjwt = require('@fastify/jwt');

dotenv.config();

fastify.register(metrics, { endpoint: '/metrics' });
fastify.register(require('@fastify/cookie'));

// fastify.register(fastifyjwt, {
// 	secret: async (req, reply) => {
// 		return getVaultValue('jwt', 'JWT_SECRET')
// 	},
// 	cookie: {
// 		cookieName: 'access_token',
// 		signed: false,
// 	}
// });

const DB_SERVICE = 'http://db-service:3000';

function createToken(user) {
	return fastify.jwt.sign({
		id: user.id,
		username: user.username,
		email: user.email,
	}, { secret: jwtSecret }); // explicit
}

//Signup local
fastify.post('/signup', async (req, reply) => {
	const {username, password, email } = req.body;
	try {
		const passwordHash = await bcrypt.hash(password, 10);

		const res = await axios.post(`${DB_SERVICE}/users`, {
			username,
			password: passwordHash,
			email,
		});
		return res.data;
	} catch (err) {
		req.log.error('Signup error:',err.response?.data || err.message);
		return reply.code(err.response?.status || 500).send(err.response?.data || { error: 'Signup failed' });
	}
});

//Login local
fastify.post('/login', async (req, reply) => {
	const { identifier, password } = req.body;

	try {

		// Try to get user by username or email
		let res = await axios.get(`${DB_SERVICE}/users/internal/${identifier}`);
		let user = res.data;

		// if (!user) {
		// 	res = await axios.post(`${DB_SERVICE}/users/${identifier}`, { params: { email: identifier } });
		// 	user = res.data[0];
		// }

		if (!user) {
			return reply.code(401).send({ error: 'Invalid credentials' });
		}

		// Verify matching passwords
		const isValid = await bcrypt.compare(password, user.password);
		if (!isValid) {
			return reply.code(401).send({ error: 'Invalid credentials' });
		}

		const token = createToken(user);

		reply
			.setCookie('access_token', token, {
				path: '/',
				httpOnly: true,
			})
			.send({ message: 'Login successful', token });

		return { id: user.id };
	} catch (err) {
		req.log.error(err.response?.data || err.message);
		return reply.code(401).send({ error: 'Invalid credentials' });
	}
});

// Middleware to verify token
fastify.decorate('authenticate', async function (request, reply) {
	try {
		const token = request.cookies.access_token;
		if (!token) {
			return reply.code(401).send('Unauthorized');
		}
		request.user = await request.jwtVerify(token);
	} catch (err) {
		reply.code(401).send({ error: 'Unauthorized' });
	}
})

// Route protégée
fastify.get('/protected', { preValidation: [fastify.authenticate] }, async (request, reply) => {
	return { msg: `Hello ${request.user.username || request.user.email}, you are authenticated.` };
});

// Logout
fastify.get('/logout', async (request, reply) => {
	reply.clearCookie('access_token', {path: '/' });
	return reply.send({ message: 'Logged out' });
})

let jwtSecret;

(async () => {
	jwtSecret = await getVaultValue('jwt', 'JWT_SECRET');

	fastify.register(fastifyjwt, {
		secret: jwtSecret,
		cookie: {
			cookieName: 'access_token',
			signed: false,
		},
	});

	// Démarre le serveur après l'enregistrement du plugin
	fastify.listen({ host: '0.0.0.0', port: 3000 }, (err, addr) => {
		if (err) {
			fastify.log.error(err);
			process.exit(1);
		}
		console.log(`Server listening at ${addr}`);
	});
})();
