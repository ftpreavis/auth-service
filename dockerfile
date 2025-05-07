# 1) build your app
FROM node:18-alpine AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

# 2) runtime image
FROM node:18-alpine

# — create the same user
RUN addgroup -S app \
 && adduser  -S -G app app

WORKDIR /app

# — copy your built files, chowning them to app:app in one go
COPY --from=builder --chown=app:app /app /app

# — switch to that user
USER app

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
