import 'dotenv/config';
interface ServerConfig {
    port: number;
    apiPrefix: string;
    env: 'development' | 'test' | 'production';
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
interface HealthCheckConfig {
    interval: number;
}
interface BackendConfig {
    server: ServerConfig;
    database: DatabaseConfig;
    discord: DiscordConfig;
    admin: AdminConfig;
    verification: VerificationConfig;
    cors: CorsConfig;
    rateLimiting: RateLimitingConfig;
    zkPassport: ZKPassportConfig;
    security: SecurityConfig;
    logging: LoggingConfig;
    healthCheck: HealthCheckConfig;
}
declare const config: BackendConfig;
export { config };
//# sourceMappingURL=config.d.ts.map