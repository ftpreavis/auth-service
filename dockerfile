FROM node:latest

WORKDIR /app

# Copy existing files if any (to avoid overwriting)
COPY . .

# Default command: init project + install Fastify if needed
CMD ["/bin/sh", "-c", "\
  if [ ! -f package.json ]; then \
    echo '📦 No package.json found, running npm init -y...'; \
    npm init -y; \
  fi && \
  echo '🚀 Installing Fastify...' && \
  npm install fastify && \
  echo '✅ Fastify installed. Project initialized at /app'"]
