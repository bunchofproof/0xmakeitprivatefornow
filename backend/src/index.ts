import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { createServer } from 'http';
import { WebSocketServer } from 'ws';
import crypto from 'crypto';
import { config } from './config';
import { logger } from './utils/logger';
import { errorHandler } from './middleware/errorHandler';
import { securityLogger, rateLimitTracker, securityHeaders, requestTimeout } from './middleware/security';
import { validateRequestSize, securityValidation } from './middleware/auth';
import { prisma } from './utils/database';

// Import encryption infrastructure
import { certificateManager } from './services/certificateManager';
import { secureKeyManager } from './services/secureKeyManager';
import { encryptedCommunicationManager } from './services/encryptedCommunicationManager';

// Import universal rate limiting system
import { rateLimitManager } from './utils/rateLimitManager';

/**
 * Async rate limiter initialization with dynamic imports
 * Prevents startup crashes in production when Redis is unavailable
 */
async function getRateLimiter() {
  if (process.env.NODE_ENV === 'production' && process.env.REDIS_URL) {
    console.log('Initializing Redis rate limiter...');
    const { Redis } = await import('ioredis');
    const { RateLimiterRedis } = await import('rate-limiter-flexible');

    const redisClient = new Redis(process.env.REDIS_URL);
    await redisClient.connect();

    return new RateLimiterRedis({
      storeClient: redisClient,
      keyPrefix: 'backend_rl',
      points: 100, // Number of requests
      duration: 60, // Per 60 seconds
    });
  } else {
    console.log('Initializing in-memory rate limiter...');
    const { RateLimiterMemory } = await import('rate-limiter-flexible');

    return new RateLimiterMemory({
      points: 100, // Number of requests
      duration: 60, // Per 60 seconds
    });
  }
}

// Import routes
import securityRoutes from './routes/security';
import verificationRoutes from './routes/verification';
import discordRoutes from './routes/discord';
import webhookRoutes from './routes/webhooks';
import adminRoutes from './routes/admin';

// Import WebSocket handler and security manager
import { handleWebSocketConnection } from './services/notificationService';
import { webSocketSecurityManager } from './services/webSocketSecurity';

const app = express();
const server = createServer(app);

// Initialize WebSocket server
const wss = new WebSocketServer({ server });

// Enhanced Security Middleware
// Request size limits (FIRST - before any processing)
app.use(express.json({ limit: '500kb' }));
app.use(express.urlencoded({ limit: '500kb', extended: true }));

// Request logging and security monitoring
app.use(securityLogger);
app.use(rateLimitTracker);

// CSP Middleware
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.nonce = nonce;
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    `style-src 'self' 'nonce-${nonce}'`,
    `script-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'"
  ].join('; '));
  next();
});

// Enhanced security headers
app.use(helmet({
  contentSecurityPolicy: false, // Disable helmet CSP since we set it manually
  crossOriginEmbedderPolicy: false,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS with enhanced security
app.use(cors({
  origin: config.cors.allowedOrigins,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'x-requested-with'],
  exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining']
}));

// Universal Rate Limiting Middleware - Async initialization
app.use(async (req, res, next) => {
  try {
    // Initialize rate limiter asynchronously if not already done
    const rateLimiter = await getRateLimiter();

    // Extract IP address
    const ip = req.headers['x-forwarded-for']?.toString().split(',')[0]?.trim() ||
               req.connection.remoteAddress ||
               req.socket.remoteAddress ||
               'unknown';

    // Check rate limit using the initialized rate limiter
    const key = `${ip}:${req.path}`;
    try {
      const result = await rateLimiter.consume(key, 1);

      // Add rate limit headers
      res.setHeader('X-Rate-Limit-Remaining', result.remainingPoints.toString());
      res.setHeader('X-Rate-Limit-Reset', new Date(Date.now() + result.msBeforeNext).toISOString());
      res.setHeader('X-Rate-Limit-Limit', '100');

      next();
    } catch (rateLimitRes: any) {
      // Rate limit exceeded
      const retryAfter = Math.ceil(rateLimitRes.msBeforeNext / 1000) || 60;
      return res.status(429).json({
        error: "Too many requests",
        message: "Rate limit exceeded. Please try again later.",
        retryAfter
      });
    }
  } catch (error) {
    logger.error('Rate limiting middleware error:', error);
    // Allow request on error but log it
    next();
  }
});

// Security validation and size limits
app.use(securityHeaders);
app.use(requestTimeout);
app.use(validateRequestSize);
app.use(securityValidation);


// Health check endpoint
app.get('/health', async (_req, res) => {
  try {
    // Always check database connection in all environments for proper health monitoring
    let databaseStatus = 'checking';
    try {
      // Check database connection with timeout
      await Promise.race([
        prisma.$queryRaw`SELECT 1`,
        new Promise((_, reject) => setTimeout(() => reject(new Error('Database connection timeout')), 5000))
      ]);
      databaseStatus = 'healthy';
    } catch (dbError) {
      logger.error('Database connection failed:', dbError);
      databaseStatus = 'unhealthy';
      // In production, return unhealthy status if database is down
      if (config.server.env === 'production') {
        return res.status(503).json({
          status: 'unhealthy',
          timestamp: new Date().toISOString(),
          error: 'Database connection failed',
          database: databaseStatus
        });
      }
    }

    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      environment: config.server.env,
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      database: databaseStatus
    });
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed',
      database: 'unknown'
    });
  }
});

// API routes
app.use('/api/security', securityRoutes);
app.use('/api/verify', verificationRoutes);
app.use('/api/discord', discordRoutes);
app.use('/api/webhooks', webhookRoutes);
app.use('/api/admin', adminRoutes);

// WebSocket connection handling
if (handleWebSocketConnection) {
  wss.on('connection', handleWebSocketConnection);
} else {
  logger.warn('WebSocket handler not available, skipping WebSocket setup');
}

// Error handling middleware (must be last)
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.originalUrl} not found`
  });
});

// Initialize encryption infrastructure
async function initializeEncryption() {
  try {
    logger.info('🔐 Initializing encryption infrastructure...');
    
    // Initialize certificate management
    await certificateManager.initialize();
    logger.info('✅ Certificate management initialized');
    
    // Initialize key management
    await secureKeyManager.initializeKeyManager();
    logger.info('✅ Key management initialized');
    
    // Initialize communication manager
    await encryptedCommunicationManager.initializeManager();
    logger.info('✅ Encrypted communication manager initialized');
    
    logger.info('🛡️ All encryption infrastructure initialized successfully');
  } catch (error) {
    logger.error('❌ Encryption initialization failed:', error);
    process.exit(1);
  }
}

// Graceful shutdown
const gracefulShutdown = async (signal: string) => {
  logger.info(`Received ${signal}, shutting down gracefully...`);

  // Close WebSocket server
  wss.close();

  // Close HTTP server
  server.close(async () => {
    logger.info('HTTP server closed');

    // Close database connection
    await prisma.$disconnect();
    logger.info('Database connection closed');

    process.exit(0);
  });

  // Force exit after 10 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

// Handle shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const PORT = config.server.port;
server.listen(PORT, async () => {
  try {
    // Initialize encryption infrastructure
    await initializeEncryption();
    
    logger.info(`🚀 Server running on port ${PORT}`);
    logger.info(`📅 Environment: ${config.server.env}`);
    logger.info(`🔒 CORS origins: ${config.cors.allowedOrigins.join(', ')}`);
    logger.info(`🗄️  Database: ${config.server.env === 'production' ? 'Production DB' : 'Connected'}`);
    logger.info(`🔐 Security: ${config.server.env === 'production' ? 'Production keys' : 'Development keys'}`);

    // Environment-specific startup messages
    if (config.server.env === 'development') {
      logger.info(`🐛 Debug logging enabled for development`);
      logger.info(`🔧 ZKPassport dev mode: ${config.zkPassport.devMode}`);
    } else if (config.server.env === 'production') {
      logger.info(`🚀 Production server started successfully`);
      logger.info(`📊 Health checks every ${config.healthCheck.interval}ms`);
    }
  } catch (error) {
    logger.error('Failed to initialize server:', error);
    process.exit(1);
  }
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err: Error) => {
  logger.error('Unhandled Promise Rejection:', err);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err: Error) => {
  logger.error('Uncaught Exception:', err);
  process.exit(1);
});

export { app, server, wss };