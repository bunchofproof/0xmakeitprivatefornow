import 'dotenv/config';
import { envsafe, str, bool, num } from 'envsafe';
// Note: shared config import removed to avoid ESM import issues in CommonJS

interface ServerConfig {
  port: number;
  apiPrefix: string;
  env: 'development' | 'test' | 'production';
  payloadLimit: string;
}

interface DatabaseConfig {
  url: string;
  prismaUrl?: string;
  nonPoolingUrl?: string;
}

interface DiscordConfig {
  token: string;
  clientId: string;
  guildId: string;
  verificationUrl: string;
}

interface AdminConfig {
  roleIds: string[];
}

interface VerifiedConfig {
  roleIds: string[];
}

interface VerificationConfig {
  maxAttempts: number;
  tokenExpiryMinutes: number;
  reminderSchedule: string;
}

interface CorsConfig {
  allowedOrigins: string[];
}

interface RateLimitingConfig {
  windowMs: number;
  maxRequests: number;
  strictWindowMs: number;
  strictMaxRequests: number;
  proofWindowMs: number;
  proofMaxRequests: number;
}

interface ZKPassportConfig {
  devMode: boolean;
  domain: string;
}

interface SecurityConfig {
  jwtSecret: string;
  encryptionKey: string;
}

interface LoggingConfig {
  level: 'debug' | 'info' | 'warn' | 'error';
  format: 'json' | 'text';
}

interface RedisConfig {
  url?: string;
}

interface DatabaseBackendConfig {
  backend: 'json' | 'sqlite' | 'prisma';
}

interface HealthCheckConfig {
  interval: number;
}

interface BackendConfig {
  server: ServerConfig;
  database: DatabaseConfig;
  databaseBackend: DatabaseBackendConfig;
  discord: DiscordConfig;
  admin: AdminConfig;
  verified: VerifiedConfig;
  verification: VerificationConfig;
  cors: CorsConfig;
  rateLimiting: RateLimitingConfig;
  redis: RedisConfig;
  zkPassport: ZKPassportConfig;
  security: SecurityConfig;
  logging: LoggingConfig;
  healthCheck: HealthCheckConfig;
  deterministicMockFingerprints: boolean;
}
interface BackendConfig {
  server: ServerConfig;
  database: DatabaseConfig;
  databaseBackend: DatabaseBackendConfig;
  discord: DiscordConfig;
  admin: AdminConfig;
  verified: VerifiedConfig;
  verification: VerificationConfig;
  cors: CorsConfig;
  rateLimiting: RateLimitingConfig;
  redis: RedisConfig;
  zkPassport: ZKPassportConfig;
  security: SecurityConfig;
  logging: LoggingConfig;
  healthCheck: HealthCheckConfig;
}

// Environment validation with comprehensive configuration
const env = envsafe({
  // Server configuration
  NODE_ENV: str({
    devDefault: 'development',
    choices: ['development', 'test', 'production'],
  }),
  PORT: num({
    devDefault: 3001,
    default: 3001,
  }),
  MAX_PAYLOAD_SIZE: str({
    devDefault: '500kb',
    default: '500kb',
  }),

  // Database backend configuration
  DATABASE_BACKEND: str({
    devDefault: 'sqlite',
    choices: ['json', 'sqlite', 'prisma'],
  }),
  DATABASE_TYPE: str({
    devDefault: 'json',
    choices: ['json', 'sqlite', 'prisma'],
  }),

  // Database configuration
  DATABASE_URL: str({
    devDefault: 'postgresql://postgres:1111@localhost:5434/dashboard',
  }),
  POSTGRES_PRISMA_URL: str({
    devDefault: 'postgresql://postgres:1111@localhost:5434/dashboard?pgbouncer=true&connect_timeout=15',
  }),
  POSTGRES_URL_NON_POOLING: str({
    devDefault: 'postgresql://postgres:1111@localhost:5434/dashboard',
  }),

  // Discord configuration
  DISCORD_BOT_TOKEN: str(),
  CLIENT_ID: str({
    devDefault: '1330186302993469561',
  }),
  GUILD_ID: str({
    devDefault: '1038523194409230387',
  }),
  VERIFICATION_URL: str({
    devDefault: 'http://192.168.1.8:3000',
  }),

  // Admin configuration
  ADMIN_ROLE_IDS: str({
    devDefault: '1408931041426804838',
  }),

  // Verified configuration
  DISCORD_VERIFIED_ROLE_IDS: str({
    devDefault: '1270431404811092121,1270431404811092121',
  }),

  // Verification configuration
  MAX_VERIFICATION_ATTEMPTS: num({
    devDefault: 3,
    default: 3,
  }),
  TOKEN_EXPIRY_MINUTES: num({
    devDefault: 15,
    default: 15,
  }),
  REMINDER_SCHEDULE: str({
    devDefault: '0 9 * * 1',
    default: '0 9 * * 1',
  }),

  // CORS configuration
  ALLOWED_ORIGINS: str({
    devDefault: 'http://192.168.1.8:3000,http://localhost:3001',
    default: 'http://localhost:3000',
  }),

  // Rate limiting
  RATE_LIMIT_WINDOW_MS: num({
    devDefault: 900000, // 15 minutes
    default: 900000,
  }),
  RATE_LIMIT_MAX_REQUESTS: num({
    devDefault: 100,
    default: 100,
  }),
  // Stricter rate limiting for sensitive endpoints
  RATE_LIMIT_STRICT_WINDOW_MS: num({
    devDefault: 900000, // 15 minutes
    default: 900000,
  }),
  RATE_LIMIT_STRICT_MAX_REQUESTS: num({
    devDefault: 5, // Very strict limit for sensitive operations
    default: 5,
  }),
  // Rate limiting for proof verification endpoint
  RATE_LIMIT_PROOF_WINDOW_MS: num({
    devDefault: 3600000, // 1 hour
    default: 3600000,
  }),
  RATE_LIMIT_PROOF_MAX_REQUESTS: num({
    devDefault: 10, // Moderate limit for verification attempts
    default: 10,
  }),

  // ZKPassport configuration
  ZK_PASSPORT_DEV_MODE: bool({
    devDefault: true,
    default: false,
  }),
  ZK_PASSPORT_DOMAIN: str({
    devDefault: 'localhost',
    default: 'localhost',
  }),

  // Security configuration with validation
  JWT_SECRET: str({
    devDefault: 'dev-jwt-secret-key-change-in-production-32-chars-min',
  }),
  ENCRYPTION_KEY: str({
    devDefault: 'dev-32-char-encryption-key-for-dev-env',
  }),

  // Logging configuration
  LOG_LEVEL: str({
    devDefault: 'debug',
    choices: ['debug', 'info', 'warn', 'error'],
    default: 'info',
  }),
  LOG_FORMAT: str({
    devDefault: 'json',
    choices: ['json', 'text'],
    default: 'json',
  }),

  // Redis configuration
  REDIS_URL: str({
    devDefault: 'redis://localhost:6379',
  }),

  // Health check configuration
  HEALTH_CHECK_INTERVAL: num({
    devDefault: 30000,
    default: 30000,
  }),

  // HMAC Secret for secure webhook communication
  BOT_WEBHOOK_SECRET: str({
    desc: 'The secret key for HMAC webhook verification.',
  }),

  // Deterministic Mock Fingerprints Configuration
  DETERMINISTIC_MOCK_FINGERPRINTS: bool({
    devDefault: false,
    default: false,
    desc: 'Enable deterministic mocking for fingerprint generation in development.',
  }),
});

// Parse configuration
const allowedOrigins = env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());
const adminRoleIds = env.ADMIN_ROLE_IDS.split(',').map(id => id.trim());
const verifiedRoleIds = env.DISCORD_VERIFIED_ROLE_IDS.split(',').map(id => id.trim());

const config: BackendConfig = {
  server: {
    port: env.PORT,
    apiPrefix: '/api',
    env: env.NODE_ENV as 'development' | 'test' | 'production',
    payloadLimit: env.MAX_PAYLOAD_SIZE,
  },
  databaseBackend: {
    backend: env.DATABASE_BACKEND as 'json' | 'sqlite' | 'prisma',
  },
  database: {
    url: env.DATABASE_URL,
    prismaUrl: env.POSTGRES_PRISMA_URL,
    nonPoolingUrl: env.POSTGRES_URL_NON_POOLING,
  },
  discord: {
    token: env.DISCORD_BOT_TOKEN,
    clientId: env.CLIENT_ID,
    guildId: env.GUILD_ID,
    verificationUrl: env.VERIFICATION_URL,
  },
  admin: {
    roleIds: adminRoleIds,
  },
  verified: {
    roleIds: verifiedRoleIds,
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
    strictWindowMs: env.RATE_LIMIT_STRICT_WINDOW_MS,
    strictMaxRequests: env.RATE_LIMIT_STRICT_MAX_REQUESTS,
    proofWindowMs: env.RATE_LIMIT_PROOF_WINDOW_MS,
    proofMaxRequests: env.RATE_LIMIT_PROOF_MAX_REQUESTS,
  },
  redis: {
    url: env.REDIS_URL,
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
    level: env.LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error',
    format: env.LOG_FORMAT as 'json' | 'text',
  },
  healthCheck: {
    interval: env.HEALTH_CHECK_INTERVAL,
  },
  deterministicMockFingerprints: env.DETERMINISTIC_MOCK_FINGERPRINTS,
};

// Enhanced validation with helpful error messages
const validateConfig = (config: BackendConfig): void => {
  // Security validations
  if (config.security.jwtSecret.length < 32) {
    throw new Error(
      'JWT_SECRET must be at least 32 characters long. ' +
      'Please generate a secure secret key for production use.'
    );
  }

  if (config.security.encryptionKey.length !== 32) {
    throw new Error(
      'ENCRYPTION_KEY must be exactly 32 characters long. ' +
      'Please ensure your encryption key is exactly 32 characters.'
    );
  }

  // Environment-specific validations
  if (config.server.env === 'production') {
    // Production-specific validations
    if (config.discord.token.includes('MTMzMDE4NjMwMjk5MzQ2OTU2MQ')) {
      throw new Error(
        'Production environment detected but using development Discord token. ' +
        'Please set DISCORD_BOT_TOKEN environment variable with production bot token.'
      );
    }

    if (config.security.jwtSecret.includes('dev-jwt-secret')) {
      throw new Error(
        'Production environment detected but using development JWT secret. ' +
        'Please set a secure JWT_SECRET environment variable for production.'
      );
    }

    if (config.security.encryptionKey.includes('dev-32-char')) {
      throw new Error(
        'Production environment detected but using development encryption key. ' +
        'Please set a secure ENCRYPTION_KEY environment variable for production.'
      );
    }

    if (config.database.url.includes('localhost')) {
      throw new Error(
        'Production environment detected but using localhost database. ' +
        'Please configure DATABASE_URL for production database.'
      );
    }

    if (config.discord.verificationUrl.includes('localhost')) {
      throw new Error(
        'Production environment detected but using localhost verification URL. ' +
        'Please set VERIFICATION_URL to your production domain.'
      );
    }

    if (!config.redis.url) {
      throw new Error(
        'Production environment detected but REDIS_URL is not set. ' +
        'Please configure REDIS_URL for Redis rate limiting in production.'
      );
    }
  }

  // Development environment suggestions
  if (config.server.env === 'development') {
    if (config.logging.level !== 'debug') {
      // Note: In development, we could log this, but since we're in config validation
      // and logger might not be available yet, we'll skip this for now
    }
  }

  // Test environment validations
  if (config.server.env === 'test') {
    if (config.discord.token === 'test_discord_token_placeholder') {
      // Note: In test environment, we could log this, but since we're in config validation
      // and logger might not be available yet, we'll skip this for now
    }
  }
};

// Run validations
validateConfig(config);

export { config };