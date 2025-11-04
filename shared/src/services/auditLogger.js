"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.auditLogger = void 0;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
class AuditLogger {
    config;
    currentLogFile = '';
    logStream = null;
    constructor(config) {
        this.config = {
            basePath: config?.basePath || path.join(process.cwd(), 'logs', 'audit'),
            retentionDays: config?.retentionDays || 90,
            maxFileSize: config?.maxFileSize || 10 * 1024 * 1024, // 10MB
            rotateInterval: config?.rotateInterval || 'daily',
            ...config,
        };
        this.ensureLogDirectory();
        this.rotateLogFile();
        this.startLogRotation();
    }
    ensureLogDirectory() {
        const dir = this.config.basePath;
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    }
    getLogFileName() {
        const now = new Date();
        const date = now.toISOString().split('T')[0]; // YYYY-MM-DD
        if (this.config.rotateInterval === 'hourly') {
            const hour = now.getUTCHours().toString().padStart(2, '0');
            return `audit-${date}-${hour}.jsonl`;
        }
        return `audit-${date}.jsonl`;
    }
    rotateLogFile() {
        const newFile = this.getLogFileName();
        if (this.currentLogFile !== newFile) {
            if (this.logStream) {
                this.logStream.end();
            }
            this.currentLogFile = newFile;
            const filePath = path.join(this.config.basePath, this.currentLogFile);
            this.logStream = fs.createWriteStream(filePath, { flags: 'a' });
        }
        this.cleanupOldLogs();
    }
    cleanupOldLogs() {
        const files = fs.readdirSync(this.config.basePath);
        const now = new Date();
        files.forEach(file => {
            if (!file.startsWith('audit-') || !file.endsWith('.jsonl'))
                return;
            const fileDate = this.extractDateFromFile(file);
            if (!fileDate)
                return;
            const ageInDays = (now.getTime() - fileDate.getTime()) / (1000 * 60 * 60 * 24);
            if (ageInDays > this.config.retentionDays) {
                fs.unlinkSync(path.join(this.config.basePath, file));
            }
        });
    }
    extractDateFromFile(filename) {
        const match = filename.match(/audit-(\d{4}-\d{2}-\d{2})/);
        if (match) {
            return new Date(match[1]);
        }
        return null;
    }
    startLogRotation() {
        const interval = this.config.rotateInterval === 'hourly' ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
        setInterval(() => this.rotateLogFile(), interval);
    }
    log(event) {
        try {
            this.rotateLogFile(); // Check if rotation is needed
            const logEntry = JSON.stringify(event) + '\n';
            if (this.logStream) {
                this.logStream.write(logEntry);
            }
        }
        catch (error) {
            console.error('Failed to write audit log:', error);
        }
    }
    // Predefined logging methods for common events
    logVerificationAttempt(userId, sessionId, verificationType, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'verification_attempt',
            userId,
            sessionId,
            verificationType,
            details,
        });
    }
    logVerificationResult(userId, sessionId, verificationType, success, details, error) {
        this.log({
            timestamp: new Date().toISOString(),
            event: success ? 'verification_success' : 'verification_failure',
            userId,
            sessionId,
            verificationType,
            success,
            details,
            error,
        });
    }
    logRoleChange(userId, actor, action, role, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: action === 'assignment' ? 'role_assignment' : 'role_removal',
            userId,
            actor,
            details: { role, ...details },
        });
    }
    logSessionEvent(userId, sessionId, action, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: action === 'start' ? 'session_start' : 'session_end',
            userId,
            sessionId,
            details,
        });
    }
    logSecurityViolation(userId, violationType, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'security_violation',
            userId,
            details: { violationType, ...details },
        });
    }
    logAdminAction(actor, action, targetUserId, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'admin_action',
            userId: targetUserId,
            actor,
            details: { action, ...details },
        });
    }
    // User communication logging methods
    logUserCommunication(userId, communicationType, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'user_communication',
            userId,
            details: { communicationType, ...details },
        });
    }
    logErrorRecovery(userId, sessionId, recoveryType, success, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: success ? 'error_recovery_success' : 'error_recovery_failure',
            userId,
            sessionId,
            success,
            details: { recoveryType, ...details },
        });
    }
    logTimeoutEvent(userId, sessionId, operation, timeoutMs, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'timeout_event',
            userId,
            sessionId,
            details: { operation, timeoutMs, ...details },
        });
    }
    logRetryAttempt(userId, sessionId, operation, attemptNumber, maxRetries, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'retry_attempt',
            userId,
            sessionId,
            details: { operation, attemptNumber, maxRetries, ...details },
        });
    }
    logProgressUpdate(userId, sessionId, step, details) {
        this.log({
            timestamp: new Date().toISOString(),
            event: 'progress_update',
            userId,
            sessionId,
            details: { step, ...details },
        });
    }
    // Query methods for retrieving logs (useful for database migration later)
    async getEvents(options = {}) {
        const { userId, event, since, until, limit = 100 } = options;
        const files = fs.readdirSync(this.config.basePath).filter(f => f.endsWith('.jsonl')).sort().reverse();
        const events = [];
        for (const file of files) {
            if (events.length >= limit)
                break;
            const filePath = path.join(this.config.basePath, file);
            const content = fs.readFileSync(filePath, 'utf-8');
            const lines = content.trim().split('\n');
            for (const line of lines) {
                if (events.length >= limit)
                    break;
                try {
                    const logEvent = JSON.parse(line);
                    // Apply filters
                    if (userId && logEvent.userId !== userId)
                        continue;
                    if (event && logEvent.event !== event)
                        continue;
                    if (since && new Date(logEvent.timestamp) < since)
                        continue;
                    if (until && new Date(logEvent.timestamp) > until)
                        continue;
                    events.push(logEvent);
                }
                catch (error) {
                    // Skip malformed lines
                    continue;
                }
            }
        }
        return events;
    }
    close() {
        if (this.logStream) {
            this.logStream.end();
            this.logStream = null;
        }
    }
}
// Export singleton instance
exports.auditLogger = new AuditLogger();
exports.default = exports.auditLogger;
//# sourceMappingURL=auditLogger.js.map