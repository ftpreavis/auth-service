const fastify = require('fastify')();
const metrics = require('fastify-metrics');
const { getVaultValue } = require('./middleware/vault-client');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const fastifyjwt = require('@fastify/jwt');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const {patch} = require("axios");

dotenv.config();

fastify.register(metrics, { endpoint: '/metrics' });
fastify.register(require('@fastify/cookie'));

fastify.register(fastifyjwt, {
	secret: async (req, reply) => {
		return getVaultValue('jwt', 'JWT_SECRET')
	},
	cookie: {
		cookieName: 'access_token',
		signed: false,
	}
});

fastify.decorate('verify2FAToken', async function (request, reply) {
	try {
		const authHeader = request.headers.authorization;

		if (!authHeader || !authHeader.startsWith('Bearer ')) {
			return reply.code(401).send({ error: 'Missing or malformed token' });
		}

		const token = authHeader.split(' ')[1];
		const payload = await fastify.jwt.verify(token);

		if (!payload.is2FAPending) {
			return reply.code(403).send({ error: 'Not a 2FA token' });
		}

		request.user = payload;
	} catch (err) {
		request.log.error('2FA token verification failed:', err.message);
		return reply.code(401).send({ error: 'Invalid 2FA token' });
	}
});


const DB_SERVICE = 'http://db-service:3000';

// Create JWT
async function createToken(user) {
	return await fastify.jwt.sign({
		id: user.id,
		username: user.username,
		email: user.email,
	});
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

		if (user.twoFAEnabled) {
			const [tempToken] = await Promise.all([fastify.jwt.sign({
				id: user.id,
				email: user.email,
				is2FAPending: true
			}, {expiresIn: '5m'})]); // durée courte

			return reply.send({
				requires2FA: true,
				tempToken,
			});
		}

		const token = await createToken(user);

		reply
			.setCookie('access_token', token, {
				path: '/',
				httpOnly: true,
			})
			.send({ message: 'Login successful', token });

	} catch (err) {
		req.log.error(err.response?.data || err.message);
		return reply.code(err.response?.status || 500).send({ error: 'Login failed' });
	}
});

fastify.post('/2fa/login', async (req, reply) => {
	const { id, token } = req.body;

	if (!id || !token) {
		return reply.code(400).send({error: 'Invalid credentials'});
	}
	try {
		const res = await axios.get(`${DB_SERVICE}/users/${id}`);
		const user = res.data;

		if (!user.twoFASecret) {
			return reply.code(400).send({ error: '2FA is not setup for this user' });
		}

		const valid = speakeasy.totp.verify({
			secret: user.twoFASecret,
			encoding: 'base32',
			token,
			window: 1,
		});

		if (!valid) {
			return reply.code(401).send({ error: 'Invalid credentials' });
		}

		const jwt = await createToken(user);

		reply
			.setCookie('access_token', jwt, {
				path: '/',
				httpOnly: true,
			})
			.send({ message: '2FA Login successful', token: jwt });
	} catch (err) {
		req.log.error(err.response?.data || err.message);
		return reply.code(err.response?.status || 500).send({ error: '2FA Login failed' });
	}
})

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

//2FA
fastify.post('/2fa/setup', { preValidation: [fastify.authenticate] }, async function (request, reply) {
	const user = request.user;

	const secret = speakeasy.generateSecret({
		name: `Transcendence (${user.email}`,
		length: 32,
	});

	try {
		await axios.patch(`${DB_SERVICE}/users/${user.id}`, {
			twoFASecret: secret.base32,
		});

		const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
		return reply.send({ qrCodeUrl, secret: secret.base32 });
	} catch (err) {
		request.log.error(err.message);
		return reply.code(500).send({ error: 'Failed to setup 2FA' });
	}
});

fastify.post('/2fa/verify', { preValidation: [fastify.authenticate] }, async (request, reply) => {
	const { token } = request.body;
	const user = request.user;

	try {
		const res = await axios.get(`${DB_SERVICE}/users/${user.id}`);
		const fullUser = res.data;

		console.log('[2FA VERIFY] user id:', user.id);
		console.log('[2FA VERIFY] secret:', fullUser.twoFASecret);
		console.log('[2FA VERIFY] token reçu:', token);

		const verified = speakeasy.totp.verify({
			secret: fullUser.twoFASecret,
			encoding: 'base32',
			token,
		});

		if (!verified) {
			console.log('[2FA VERIFY] Code TOTP invalide');
			return reply.code(400).send({ error: 'Invalid 2FA token' });
		}

		console.log('[2FA VERIFY] Code TOTP validé ✅');

		await axios.patch(`${DB_SERVICE}/users/${user.id}`, {
			twoFAEnabled: true,
		});

		return reply.send({ message: '2FA activated' });
	} catch (err) {
		request.log.error('2FA activation error:', err.response?.data || err.message);
		return reply.code(500).send({ error: 'Failed to activate 2FA' });
	}
});


fastify.listen({ host: '0.0.0.0', port: 3000}, (err, addr) => {
	if (err) {
		fastify.log.error(err);
		process.exit(1);
	}
	console.log(`Server listening at ${addr}`)
})
