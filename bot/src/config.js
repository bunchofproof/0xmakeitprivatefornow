"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
require("dotenv/config");
const envsafe_1 = require("envsafe");
// Environment validation
const env = (0, envsafe_1.envsafe)({
    NODE_ENV: (0, envsafe_1.str)({
        devDefault: 'development',
        choices: ['development', 'test', 'production'],
    }),
    DISCORD_TOKEN: (0, envsafe_1.str)(),
    CLIENT_ID: (0, envsafe_1.str)(),
    GUILD_ID: (0, envsafe_1.str)(),
    DATABASE_URL: (0, envsafe_1.str)(),
    VERIFICATION_URL: (0, envsafe_1.str)(),
    ADMIN_ROLE_IDS: (0, envsafe_1.str)(),
    MAX_VERIFICATION_ATTEMPTS: (0, envsafe_1.num)({
        devDefault: 3,
        default: 3,
    }),
    TOKEN_EXPIRY_MINUTES: (0, envsafe_1.num)({
        devDefault: 15,
        default: 15,
    }),
    REMINDER_SCHEDULE: (0, envsafe_1.str)({
        devDefault: '0 9 * * 1', // Every Monday at 9 AM
        default: '0 9 * * 1',
    }),
    LOG_LEVEL: (0, envsafe_1.str)({
        devDefault: 'info',
        choices: ['debug', 'info', 'warn', 'error'],
        default: 'info',
    }),
    LOG_FORMAT: (0, envsafe_1.str)({
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
exports.config = {
    env: env.NODE_ENV,
    bot: {
        discordToken: env.DISCORD_TOKEN,
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
    logging: {
        level: env.LOG_LEVEL,
        format: env.LOG_FORMAT,
    },
};
// Validate configuration
if (adminRoleIds.length === 0) {
    throw new Error('At least one admin role ID must be specified in ADMIN_ROLE_IDS');
}
if (exports.config.bot.tokenExpiryMinutes < 1 || exports.config.bot.tokenExpiryMinutes > 60) {
    throw new Error('TOKEN_EXPIRY_MINUTES must be between 1 and 60');
}
if (exports.config.bot.maxVerificationAttempts < 1 || exports.config.bot.maxVerificationAttempts > 10) {
    throw new Error('MAX_VERIFICATION_ATTEMPTS must be between 1 and 10');
}
//# sourceMappingURL=config.js.map