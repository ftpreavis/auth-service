# ---------------------------------------------------------------------------- #
#                             Production Dockerfile                            #
# ---------------------------------------------------------------------------- #

# ------------------------------ Build omit dev ------------------------------ #

FROM node:latest AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

# ----------------------------- Build final image ---------------------------- #

FROM node:latest

WORKDIR /app

COPY --from=builder /app /app

RUN groupadd -r app && useradd -m -g app app
USER app

EXPOSE 3000

ENV NODE_ENV=production
ENV PORT=3000

CMD ["node", "index.js"]
