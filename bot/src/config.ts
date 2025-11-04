import 'dotenv/config';
import { envsafe, str, num } from 'envsafe';

// Local interface definition to avoid import issues
interface BotConfig {
  discordBotToken: string;
  jwtSecret: string;
  clientId: string;
  guildId: string;
  databaseUrl: string;
  verificationUrl: string;
  adminRoleIds: string[];
  maxVerificationAttempts: number;
  tokenExpiryMinutes: number;
  reminderSchedule: string;
}

interface CryptoConfig {
  algorithm: string;
  secretLength: number;
  tokenLength: number;
}

interface DatabaseConfig {
  url: string;
  provider: 'postgresql' | 'mysql' | 'sqlite';
  ssl?: boolean;
}

type Environment = 'development' | 'test' | 'production';

interface RateLimitConfig {
  command: {
    points: number;
    duration: number;
  };
}

interface AppConfig {
  env: Environment;
  bot: BotConfig;
  crypto: CryptoConfig;
  database: DatabaseConfig;
  rateLimit: RateLimitConfig;
  logging: {
    level: 'debug' | 'info' | 'warn' | 'error';
    format: 'json' | 'text';
  };
}

// Environment validation
const env = envsafe({
  NODE_ENV: str({
    devDefault: 'development',
    choices: ['development', 'test', 'production'],
  }),
  DISCORD_BOT_TOKEN: str(),
  JWT_SECRET: str({
    devDefault: 'dev-jwt-secret-key-change-in-production-32-chars-min',
  }),
  CLIENT_ID: str(),
  GUILD_ID: str(),
  DATABASE_URL: str(),
  VERIFICATION_URL: str(),
  BOT_WEBHOOK_SECRET: str({
    desc: 'The secret key for HMAC webhook verification.',
  }),
  ADMIN_ROLE_IDS: str(),
  MAX_VERIFICATION_ATTEMPTS: num({
    devDefault: 3,
    default: 3,
  }),
  RATE_LIMIT_MAX_REQUESTS: num({
    devDefault: 1,
    default: 1,
  }),
  RATE_LIMIT_WINDOW_MINUTES: num({
    devDefault: 1,
    default: 1,
  }),
  TOKEN_EXPIRY_MINUTES: num({
    devDefault: 15,
    default: 15,
  }),
  REMINDER_SCHEDULE: str({
    devDefault: '0 9 * * 1', // Every Monday at 9 AM
    default: '0 9 * * 1',
  }),
  LOG_LEVEL: str({
    devDefault: 'info',
    choices: ['debug', 'info', 'warn', 'error'],
    default: 'info',
  }),
  LOG_FORMAT: str({
    devDefault: 'text',
    choices: ['json', 'text'],
    default: 'text',
  }),
});

// Parse admin role IDs
const adminRoleIds = env.ADMIN_ROLE_IDS
  ? env.ADMIN_ROLE_IDS.split(',').map(id => id.trim())
  : [];

// Configuration object
export const config: AppConfig = {
  env: env.NODE_ENV as Environment,
  bot: {
    discordBotToken: env.DISCORD_BOT_TOKEN,
    jwtSecret: env.JWT_SECRET,
    clientId: env.CLIENT_ID,
    guildId: env.GUILD_ID,
    databaseUrl: env.DATABASE_URL,
    verificationUrl: env.VERIFICATION_URL,
    adminRoleIds,
    maxVerificationAttempts: env.MAX_VERIFICATION_ATTEMPTS,
    tokenExpiryMinutes: env.TOKEN_EXPIRY_MINUTES,
    reminderSchedule: env.REMINDER_SCHEDULE,
  },
  crypto: {
    algorithm: 'aes-256-gcm',
    secretLength: 32,
    tokenLength: 32,
  },
  database: {
    url: env.DATABASE_URL,
    provider: env.DATABASE_URL.includes('postgresql') ? 'postgresql' : 'sqlite',
    ssl: env.NODE_ENV === 'production',
  },
  rateLimit: {
    command: {
      points: env.RATE_LIMIT_MAX_REQUESTS,
      duration: env.RATE_LIMIT_WINDOW_MINUTES,
    },
  },
  logging: {
    level: env.LOG_LEVEL as 'debug' | 'info' | 'warn' | 'error',
    format: env.LOG_FORMAT as 'json' | 'text',
  },
};

// Validate configuration
if (!config.bot.discordBotToken) {
  throw new Error('DISCORD_BOT_TOKEN is required and must be set');
}

if (!config.bot.jwtSecret) {
  throw new Error('JWT_SECRET is required and must be set');
}

if (config.bot.jwtSecret.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters long. Please generate a secure secret key for production use.');
}

if (adminRoleIds.length === 0) {
  throw new Error('At least one admin role ID must be specified in ADMIN_ROLE_IDS');
}

if (config.bot.tokenExpiryMinutes < 1 || config.bot.tokenExpiryMinutes > 60) {
  throw new Error('TOKEN_EXPIRY_MINUTES must be between 1 and 60');
}

if (config.bot.maxVerificationAttempts < 1 || config.bot.maxVerificationAttempts > 10) {
  throw new Error('MAX_VERIFICATION_ATTEMPTS must be between 1 and 10');
}

if (!env.BOT_WEBHOOK_SECRET) {
  throw new Error('BOT_WEBHOOK_SECRET is required and must be set');
}