# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM node:20-slim AS builder
WORKDIR /app

# OpenSSL is required for Prisma to detect the system SSL version and
# generate the correct engine binary (debian-openssl-3.0.x)
RUN apt-get update -y && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Install dependencies first (cached layer)
COPY backend/package*.json ./
RUN npm ci

# Copy Node.js backend source + Prisma schema
COPY backend/src ./src
COPY backend/tsconfig.json ./tsconfig.json
COPY backend/prisma ./prisma

# Copy DEMO.html (frontend) into build context
COPY DEMO.html ./DEMO.html

# Generate Prisma client + compile TypeScript
RUN npx prisma generate
RUN npm run build

# ── Stage 2: Run ──────────────────────────────────────────────────────────────
FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production

# OpenSSL required at runtime for Prisma engine to load libssl.so.3
RUN apt-get update -y && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# Production dependencies only
COPY backend/package*.json ./
RUN npm ci --omit=dev

# Copy compiled output from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Prisma schema (needed for migrate deploy)
COPY backend/prisma ./prisma

# Frontend served by Express at GET /
COPY DEMO.html ./DEMO.html

EXPOSE 3001

# Run DB migrations (non-blocking — server starts even if migrate has issues)
# then start the Express server. Railway injects PORT automatically.
CMD ["node", "dist/index.js"]
