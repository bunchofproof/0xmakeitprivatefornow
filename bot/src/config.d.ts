import 'dotenv/config';
interface BotConfig {
    discordToken: string;
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
interface AppConfig {
    env: Environment;
    bot: BotConfig;
    crypto: CryptoConfig;
    database: DatabaseConfig;
    logging: {
        level: 'debug' | 'info' | 'warn' | 'error';
        format: 'json' | 'text';
    };
}
export declare const config: AppConfig;
export {};
//# sourceMappingURL=config.d.ts.map