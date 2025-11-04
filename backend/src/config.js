"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
require("dotenv/config");
const envsafe_1 = require("envsafe");
// Environment validation with comprehensive configuration
const env = (0, envsafe_1.envsafe)({
    // Server configuration
    NODE_ENV: (0, envsafe_1.str)({
        devDefault: 'development',
        choices: ['development', 'test', 'production'],
    }),
    PORT: (0, envsafe_1.num)({
        devDefault: 3001,
        default: 3001,
    }),
    // Database configuration
    DATABASE_URL: (0, envsafe_1.str)({
        devDefault: 'postgresql://postgres:1111@localhost:5434/dashboard',
    }),
    POSTGRES_PRISMA_URL: (0, envsafe_1.str)({
        devDefault: 'postgresql://postgres:1111@localhost:5434/dashboard?pgbouncer=true&connect_timeout=15',
    }),
    POSTGRES_URL_NON_POOLING: (0, envsafe_1.str)({
        devDefault: 'postgresql://postgres:1111@localhost:5434/dashboard',
    }),
    // Discord configuration
    DISCORD_BOT_TOKEN: (0, envsafe_1.str)(),
    CLIENT_ID: (0, envsafe_1.str)({
        devDefault: '1330186302993469561',
    }),
    GUILD_ID: (0, envsafe_1.str)({
        devDefault: '1038523194409230387',
    }),
    VERIFICATION_URL: (0, envsafe_1.str)({
        devDefault: 'http://192.168.1.8:3000',
    }),
    // Admin configuration
    ADMIN_ROLE_IDS: (0, envsafe_1.str)({
        devDefault: '1408931041426804838',
    }),
    // Verification configuration
    MAX_VERIFICATION_ATTEMPTS: (0, envsafe_1.num)({
        devDefault: 3,
        default: 3,
    }),
    TOKEN_EXPIRY_MINUTES: (0, envsafe_1.num)({
        devDefault: 15,
        default: 15,
    }),
    REMINDER_SCHEDULE: (0, envsafe_1.str)({
        devDefault: '0 9 * * 1',
        default: '0 9 * * 1',
    }),
    // CORS configuration
    ALLOWED_ORIGINS: (0, envsafe_1.str)({
        devDefault: 'http://192.168.1.8:3000,http://localhost:3001',
        default: 'http://localhost:3000',
    }),
    // Rate limiting
    RATE_LIMIT_WINDOW_MS: (0, envsafe_1.num)({
        devDefault: 900000, // 15 minutes
        default: 900000,
    }),
    RATE_LIMIT_MAX_REQUESTS: (0, envsafe_1.num)({
        devDefault: 100,
        default: 100,
    }),
    // ZKPassport configuration
    ZK_PASSPORT_DEV_MODE: (0, envsafe_1.bool)({
        devDefault: true,
        default: false,
    }),
    ZK_PASSPORT_DOMAIN: (0, envsafe_1.str)({
        devDefault: 'localhost',
        default: 'localhost',
    }),
    // Security configuration with validation
    JWT_SECRET: (0, envsafe_1.str)({
        devDefault: 'dev-jwt-secret-key-change-in-production-32-chars-min',
    }),
    ENCRYPTION_KEY: (0, envsafe_1.str)({
        devDefault: 'dev-32-char-encryption-key-for-dev-env',
    }),
    // Logging configuration
    LOG_LEVEL: (0, envsafe_1.str)({
        devDefault: 'debug',
        choices: ['debug', 'info', 'warn', 'error'],
        default: 'info',
    }),
    LOG_FORMAT: (0, envsafe_1.str)({
        devDefault: 'json',
        choices: ['json', 'text'],
        default: 'json',
    }),
    // Health check configuration
    HEALTH_CHECK_INTERVAL: (0, envsafe_1.num)({
        devDefault: 30000,
        default: 30000,
    }),
});
// Parse configuration
const allowedOrigins = env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());
const adminRoleIds = env.ADMIN_ROLE_IDS.split(',').map(id => id.trim());
const config = {
    server: {
        port: env.PORT,
        apiPrefix: '/api',
        env: env.NODE_ENV,
    },
    database: {
        url: env.DATABASE_URL,
        prismaUrl: env.POSTGRES_PRISMA_URL,
        nonPoolingUrl: env.POSTGRES_URL_NON_POOLING,
    },
    discord: {
        token: env.DISCORD_TOKEN,
        clientId: env.CLIENT_ID,
        guildId: env.GUILD_ID,
        verificationUrl: env.VERIFICATION_URL,
    },
    admin: {
        roleIds: adminRoleIds,
    },
    verification: {
        maxAttempts: env.MAX_VERIFICATION_ATTEMPTS,
        tokenExpiryMinutes: env.TOKEN_EXPIRY_MINUTES,
        reminderSchedule: env.REMINDER_SCHEDULE,
    },
    cors: {
        allowedOrigins,
    },
    rateLimiting: {
        windowMs: env.RATE_LIMIT_WINDOW_MS,
        maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
    },
    zkPassport: {
        devMode: env.ZK_PASSPORT_DEV_MODE,
        domain: env.ZK_PASSPORT_DOMAIN,
    },
    security: {
        jwtSecret: env.JWT_SECRET,
        encryptionKey: env.ENCRYPTION_KEY,
    },
    logging: {
        level: env.LOG_LEVEL,
        format: env.LOG_FORMAT,
    },
    healthCheck: {
        interval: env.HEALTH_CHECK_INTERVAL,
    },
};
exports.config = config;
// Enhanced validation with helpful error messages
const validateConfig = (config) => {
    // Security validations
    if (config.security.jwtSecret.length < 32) {
        throw new Error('JWT_SECRET must be at least 32 characters long. ' +
            'Please generate a secure secret key for production use.');
    }
    if (config.security.encryptionKey.length !== 32) {
        throw new Error('ENCRYPTION_KEY must be exactly 32 characters long. ' +
            'Please ensure your encryption key is exactly 32 characters.');
    }
    // Environment-specific validations
    if (config.server.env === 'production') {
        // Production-specific validations
        if (config.discord.token.includes('MTMzMDE4NjMwMjk5MzQ2OTU2MQ')) {
            throw new Error('Production environment detected but using development Discord token. ' +
                'Please set DISCORD_TOKEN environment variable with production bot token.');
        }
        if (config.security.jwtSecret.includes('dev-jwt-secret')) {
            throw new Error('Production environment detected but using development JWT secret. ' +
                'Please set a secure JWT_SECRET environment variable for production.');
        }
        if (config.security.encryptionKey.includes('dev-32-char')) {
            throw new Error('Production environment detected but using development encryption key. ' +
                'Please set a secure ENCRYPTION_KEY environment variable for production.');
        }
        if (config.database.url.includes('localhost')) {
            throw new Error('Production environment detected but using localhost database. ' +
                'Please configure DATABASE_URL for production database.');
        }
        if (config.discord.verificationUrl.includes('localhost')) {
            throw new Error('Production environment detected but using localhost verification URL. ' +
                'Please set VERIFICATION_URL to your production domain.');
        }
    }
    // Development environment suggestions
    if (config.server.env === 'development') {
        if (config.logging.level !== 'debug') {
            console.warn('Development environment: Consider using LOG_LEVEL=debug for detailed logging during development.');
        }
    }
    // Test environment validations
    if (config.server.env === 'test') {
        if (config.discord.token === 'test_discord_token_placeholder') {
            console.warn('Test environment: Using placeholder Discord token. ' +
                'Set DISCORD_TOKEN for actual Discord integration testing.');
        }
    }
};
// Run validations
validateConfig(config);
//# sourceMappingURL=config.js.map