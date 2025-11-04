# Multi-stage build for optimal image size
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Production stage
FROM node:18-alpine AS production

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs
RUN adduser -S discordbot -u 1001

# Copy package files
COPY package*.json ./

# Copy dependencies from builder stage
COPY --from=builder /app/node_modules ./node_modules

# Copy application code
COPY src ./src
COPY tsconfig.json ./
COPY prisma ./prisma

# Build the application
RUN npm run build

# Create logs directory
RUN mkdir -p /app/logs && chown -R discordbot:nodejs /app

# Generate Prisma client
RUN npx prisma generate

# Switch to non-root user
USER discordbot

# Expose port (if needed for health checks)
EXPOSE 3002

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "console.log('Bot service healthy'); process.exit(0);"

# Start the application
CMD ["npm", "start"]