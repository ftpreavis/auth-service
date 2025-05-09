FROM node:24-bookworm AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

FROM node:24-bookworm
WORKDIR /app

# — copy your built files, chowning them to app:app in one go
COPY --from=builder --chown=app:app /app /app

# — switch to that user
USER app

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
