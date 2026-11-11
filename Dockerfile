# ==============================================================================
# Hardened Multi-Stage Dockerfile for Production Node.js Backend
# ==============================================================================

# Stage 1: Build & Dependencies
FROM node:22-alpine AS dependencies
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production --ignore-scripts

# Stage 2: Hardened Runtime Container
FROM node:22-alpine AS runner
WORKDIR /app

# Security: Set production environment
ENV NODE_ENV=production
ENV PORT=4000
ENV HOST=0.0.0.0

# Copy installed production dependencies and source files
COPY --chown=node:node --from=dependencies /app/node_modules ./node_modules
COPY --chown=node:node package*.json ./
COPY --chown=node:node src ./src

# AppSec: Run as unprivileged non-root user 'node'
USER node

# Health check container probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:4000/health/live || exit 1

EXPOSE 4000

CMD ["node", "src/server.js"]
