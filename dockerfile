FROM node:24-bookworm AS builder
WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

FROM node:24-bookworm
WORKDIR /app

COPY --from=builder /app /app

RUN addgroup -S app && adduser -S -G app app
USER app

ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "index.js"]
