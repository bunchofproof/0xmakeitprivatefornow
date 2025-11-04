import { logger } from '../utils/logger';
import { databaseDriver } from '../utils/databaseDrivers';

/**
 * Session cleanup service for maintaining database health
 * by removing expired and compromised verification sessions.
 */
export class SessionCleanupService {
  private readonly MAX_USAGE_COUNT = 3; // Maximum usage count before forced expiry
  private readonly REPLAY_WINDOW = 1000; // 1 second window for replay detection

  constructor() {
    logger.info('Session Cleanup Service initialized', {
      maxUsageCount: this.MAX_USAGE_COUNT,
      replayWindow: this.REPLAY_WINDOW
    });
  }

  /**
   * Perform security cleanup of expired and compromised sessions
   */
  async performSecurityCleanup(): Promise<{
    expiredSessions: number;
    compromisedSessions: number;
    replayAttempts: number;
    errors: string[];
  }> {
    try {
      const errors: string[] = [];
      let expiredSessions = 0;
      let compromisedSessions = 0;
      let replayAttempts = 0;

      await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx: any) => {
        const sessions = await tx.read('verification-sessions.json');
        const currentTime = new Date();

        const cleanedSessions = sessions.filter((session: any) => {
          const expiresAt = new Date(session.expiresAt);

          // Remove expired sessions
          if (currentTime > expiresAt) {
            expiredSessions++;
            return false;
          }

          // Remove compromised sessions (multiple usage attempts)
          if (session.usageCount && session.usageCount > this.MAX_USAGE_COUNT) {
            compromisedSessions++;
            return false;
          }

          // Remove sessions with replay attempts (simplified detection)
          if (session.lastUsedAt) {
            const timeSinceLastUse = currentTime.getTime() - new Date(session.lastUsedAt).getTime();
            if (timeSinceLastUse < this.REPLAY_WINDOW) {
              replayAttempts++;
              return false;
            }
          }

          return true;
        });

        await tx.write('verification-sessions.json', cleanedSessions);

        await this.logSecurityEvent({
          sessionId: 'cleanup',
          discordUserId: 'system',
          eventType: 'cleanup_completed',
          severity: 'info',
          description: `Security cleanup completed: ${expiredSessions} expired, ${compromisedSessions} compromised, ${replayAttempts} replay sessions removed`,
          metadata: {
            expiredSessions,
            compromisedSessions,
            replayAttempts,
            remainingSessions: cleanedSessions.length
          }
        });
      });

      return {
        expiredSessions,
        compromisedSessions,
        replayAttempts,
        errors
      };

    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Security cleanup failed:', err);
      return {
        expiredSessions: 0,
        compromisedSessions: 0,
        replayAttempts: 0,
        errors: [err.message]
      };
    }
  }

  /**
   * Log security event
   */
  private async logSecurityEvent(event: {
    sessionId: string;
    discordUserId: string;
    eventType: string;
    severity: 'info' | 'warning' | 'error' | 'high';
    description: string;
    metadata?: any;
  }): Promise<void> {
    try {
      logger.warn(`Security Event: ${event.eventType}`, {
        sessionId: event.sessionId,
        discordUserId: event.discordUserId,
        severity: event.severity,
        description: event.description,
        ...event.metadata
      });
    } catch (error) {
      logger.error('Failed to log security event:', error instanceof Error ? error : new Error(String(error)));
    }
  }
}

export const sessionCleanupService = new SessionCleanupService();