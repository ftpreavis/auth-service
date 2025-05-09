# 1) build your app
FROM node:24 AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production
COPY . .

# 2) runtime image
FROM node:24
WORKDIR /app

# Copy everything (no chown needed)
COPY --from=builder /app /app

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
