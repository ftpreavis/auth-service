import fastify from 'fastify'

const server = fastify()

server.get('/', async (request, reply) => {
	return 'pong\n'
})

server.listen({ host: '0.0.0.0', port: 3000}, (err, addr) => {
	if (err) {
		console.error(err)
		process.exit(1)
	}
	console.log(`Serveir listening at ${addr}`)
})
