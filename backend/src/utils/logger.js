"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const config_1 = require("../config");
const auditLogger_1 = require("../../../shared/src/services/auditLogger");
class Logger {
    formatLog(level, message, meta) {
        const entry = {
            timestamp: new Date().toISOString(),
            level: level.toUpperCase(),
            message,
        };
        if (meta) {
            entry.meta = meta;
        }
        if (config_1.config.logging.format === 'json') {
            return JSON.stringify(entry);
        }
        else {
            const metaStr = meta ? ` | ${JSON.stringify(meta)}` : '';
            return `[${entry.timestamp}] ${entry.level}: ${message}${metaStr}`;
        }
    }
    log(level, message, meta) {
        const formattedLog = this.formatLog(level, message, meta);
        switch (level) {
            case 'error':
                console.error(formattedLog);
                break;
            case 'warn':
                console.warn(formattedLog);
                break;
            case 'info':
                console.info(formattedLog);
                break;
            case 'debug':
                console.debug(formattedLog);
                break;
            default:
                console.log(formattedLog);
        }
    }
    debug(message, meta) {
        if (['debug', 'info', 'warn', 'error'].indexOf(config_1.config.logging.level) <= 0) {
            this.log('debug', message, meta);
        }
    }
    info(message, meta) {
        if (['info', 'warn', 'error'].indexOf(config_1.config.logging.level) <= 1) {
            this.log('info', message, meta);
        }
    }
    warn(message, meta) {
        if (['warn', 'error'].indexOf(config_1.config.logging.level) <= 2) {
            this.log('warn', message, meta);
        }
    }
    error(message, meta) {
        if (config_1.config.logging.level === 'error') {
            this.log('error', message, meta);
        }
    }
    // Utility method for logging errors with stack traces
    logError(error, context) {
        const meta = {
            error: error instanceof Error ? {
                name: error.name,
                message: error.message,
                stack: error.stack,
            } : error,
            context,
        };
        this.error('An error occurred', meta);
    }
    // Utility method for logging API requests
    logRequest(method, url, statusCode, duration) {
        const meta = {
            method,
            url,
            statusCode,
            duration: duration ? `${duration}ms` : undefined,
        };
        this.info('API Request', meta);
    }
    // Utility method for logging database operations
    logDatabase(operation, table, duration, meta) {
        const logMeta = {
            ...meta,
            operation,
            table,
            duration: duration ? `${duration}ms` : undefined,
        };
        this.debug('Database Operation', logMeta);
    }
    // Audit logging methods
    logSecurityEvent(event, userId, details) {
        auditLogger_1.auditLogger.log({
            timestamp: new Date().toISOString(),
            event: 'security_violation',
            userId,
            details,
        });
        this.warn(`Security Event: ${event}`, { userId, details });
    }
    logAdminAction(action, actor, targetUserId, details) {
        auditLogger_1.auditLogger.logAdminAction(actor, action, targetUserId, details);
        this.info(`Admin Action: ${action}`, { actor, targetUserId, details });
    }
}
exports.logger = new Logger();
//# sourceMappingURL=logger.js.map