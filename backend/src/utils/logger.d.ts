declare class Logger {
    private formatLog;
    private log;
    debug(message: string, meta?: any): void;
    info(message: string, meta?: any): void;
    warn(message: string, meta?: any): void;
    error(message: string, meta?: any): void;
    logError(error: Error | unknown, context?: string): void;
    logRequest(method: string, url: string, statusCode?: number, duration?: number): void;
    logDatabase(operation: string, table: string, duration?: number, meta?: any): void;
    logSecurityEvent(event: string, userId?: string, details?: any): void;
    logAdminAction(action: string, actor: string, targetUserId?: string, details?: any): void;
}
export declare const logger: Logger;
export {};
//# sourceMappingURL=logger.d.ts.map