# syntax=docker/dockerfile:1

# ============================================================================
# Stage 1: Build Frontend (Vite + React) & Backend (TypeScript -> Node 24 ESM)
# ============================================================================
FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS builder

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.server.json vite.config.ts vite.mobile.config.ts ./
COPY public ./public
COPY src ./src
COPY mobile ./mobile

RUN npm run build && npm prune --omit=dev

# ============================================================================
# Stage 2: Minimal Hardened Production Runtime (Node 24 Built-in SQLite & Crypto)
# ============================================================================
FROM node:24-bookworm-slim AS runner

WORKDIR /app

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/data \
    SESSION_TTL_HOURS=72

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data && chown -R node:node /data /app

COPY --chown=node:node --from=builder /app/package.json ./package.json
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/dist ./dist

USER node

VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/api/v1/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "dist/server/server/index.js"]
