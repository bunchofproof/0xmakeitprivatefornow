"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const config_1 = require("../config");
const auditLogger_1 = require("../../../shared/src/services/auditLogger");
class Logger {
    isJsonFormat() {
        return config_1.config.logging.format === 'json';
    }
    formatLog(level, message, error, data) {
        const logEntry = {
            level,
            message,
            timestamp: new Date().toISOString(),
            ...(error && { error: error.message }),
            ...(data && { data })
        };
        if (this.isJsonFormat()) {
            return JSON.stringify(logEntry);
        }
        const timestamp = new Date().toLocaleTimeString();
        let formatted = `[${timestamp}] ${level.toUpperCase()}: ${message}`;
        if (error) {
            formatted += `\nError: ${error.message}`;
            if (error.stack && config_1.config.logging.level === 'debug') {
                formatted += `\nStack: ${error.stack}`;
            }
        }
        if (data && config_1.config.logging.level === 'debug') {
            formatted += `\nData: ${JSON.stringify(data, null, 2)}`;
        }
        return formatted;
    }
    debug(message, data) {
        if (this.shouldLog('debug')) {
            console.log(this.formatLog('debug', message, undefined, data));
        }
    }
    info(message, data) {
        if (this.shouldLog('info')) {
            console.log(this.formatLog('info', message, undefined, data));
        }
    }
    warn(message, data) {
        if (this.shouldLog('warn')) {
            console.warn(this.formatLog('warn', message, undefined, data));
        }
    }
    error(message, error, data) {
        if (this.shouldLog('error')) {
            console.error(this.formatLog('error', message, error, data));
        }
    }
    // Audit logging methods
    logVerificationAttempt(userId, sessionId, verificationType, details) {
        auditLogger_1.auditLogger.logVerificationAttempt(userId, sessionId, verificationType, details);
        this.info(`Verification attempt: ${verificationType}`, { userId, sessionId, verificationType, details });
    }
    logVerificationResult(userId, sessionId, verificationType, success, details, error) {
        auditLogger_1.auditLogger.logVerificationResult(userId, sessionId, verificationType, success, details, error);
        if (success) {
            this.info(`Verification success: ${verificationType}`, { userId, sessionId, verificationType, details });
        }
        else {
            this.warn(`Verification failure: ${verificationType}`, { userId, sessionId, verificationType, error, details });
        }
    }
    logSecurityViolation(userId, violationType, details) {
        auditLogger_1.auditLogger.logSecurityViolation(userId, violationType, details);
        this.error(`Security violation: ${violationType}`, undefined, { userId, violationType, details });
    }
    shouldLog(level) {
        const levels = ['debug', 'info', 'warn', 'error'];
        const currentLevelIndex = levels.indexOf(config_1.config.logging.level);
        const messageLevelIndex = levels.indexOf(level);
        return messageLevelIndex >= currentLevelIndex;
    }
}
exports.logger = new Logger();
//# sourceMappingURL=logger.js.map