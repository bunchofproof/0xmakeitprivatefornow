declare class Logger {
    private isJsonFormat;
    private formatLog;
    debug(message: string, data?: any): void;
    info(message: string, data?: any): void;
    warn(message: string, data?: any): void;
    error(message: string, error?: Error, data?: any): void;
    logVerificationAttempt(userId: string, sessionId: string, verificationType: string, details?: any): void;
    logVerificationResult(userId: string, sessionId: string, verificationType: string, success: boolean, details?: any, error?: string): void;
    logSecurityViolation(userId: string, violationType: string, details?: any): void;
    private shouldLog;
}
export declare const logger: Logger;
export {};
//# sourceMappingURL=logger.d.ts.map