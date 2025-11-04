/**
 * Session cleanup configuration
 */
export interface CleanupConfig {
    sessionRetentionHours: number;
    adminVerificationRetentionHours: number;
    batchSize: number;
    dryRun: boolean;
}
/**
 * Default cleanup configuration
 */
export declare const defaultCleanupConfig: CleanupConfig;
/**
 * Session management utilities for production cleanup
 */
export declare class SessionManager {
    private config;
    constructor(config?: Partial<CleanupConfig>);
    /**
     * Clean up expired verification sessions
     */
    cleanupExpiredSessions(): Promise<{
        deletedCount: number;
        errors: string[];
    }>;
    /**
     * Clean up expired admin verifications (those past their expiry date)
     */
    cleanupExpiredAdminVerifications(): Promise<{
        deactivatedCount: number;
        errors: string[];
    }>;
    /**
     * Clean up old verification history records (older than retention period)
     */
    cleanupOldVerificationHistory(retentionDays?: number): Promise<{
        deletedCount: number;
        errors: string[];
    }>;
    /**
     * Get session health statistics
     */
    getSessionHealthStats(): Promise<{
        totalSessions: number;
        expiredSessions: number;
        activeSessions: number;
        totalAdminVerifications: number;
        activeAdminVerifications: number;
        expiredAdminVerifications: number;
        totalHistoryRecords: number;
    }>;
    /**
     * Perform full maintenance cleanup
     */
    performFullMaintenance(): Promise<{
        sessionsCleaned: number;
        adminVerificationsDeactivated: number;
        historyCleaned: number;
        errors: string[];
    }>;
}
export declare const sessionManager: SessionManager;
//# sourceMappingURL=sessionManager.d.ts.map