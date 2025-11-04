import { logger } from '../utils/logger';
import { databaseDriver } from '../utils/databaseDrivers';

// Constants moved from EnhancedSessionSecurityManager
const MAX_USAGE_COUNT = 3; // Maximum usage count before forced expiry
const REPLAY_WINDOW = 1000; // 1 second window for replay detection

/**
 * Get session security statistics
 */
export async function getSessionSecurityStats(): Promise<{
  totalSessions: number;
  activeSessions: number;
  expiredSessions: number;
  compromisedSessions: number;
  replayAttempts: number;
  bindingViolations: number;
  securityEvents: number;
  timestamp: Date;
  systemHealthy: boolean;
}> {
  try {
    const sessions = await databaseDriver.readFile('verification-sessions.json');
    const currentTime = new Date();

    let totalSessions = 0;
    let activeSessions = 0;
    let expiredSessions = 0;
    let compromisedSessions = 0;
    let replayAttempts = 0;
    let bindingViolations = 0;
    let securityEvents = 0;

    for (const session of sessions) {
      totalSessions++;
      const expiresAt = new Date(session.expiresAt);

      if (currentTime > expiresAt) {
        expiredSessions++;
      } else if (!session.used) {
        activeSessions++;
      }

      // Count compromised sessions (those with multiple usage attempts)
      if (session.usageCount && session.usageCount > MAX_USAGE_COUNT) {
        compromisedSessions++;
      }

      // Count replay attempts (based on replay detection logic)
      if (session.lastUsedAt) {
        const timeSinceLastUse = currentTime.getTime() - new Date(session.lastUsedAt).getTime();
        if (timeSinceLastUse < REPLAY_WINDOW) {
          replayAttempts++;
        }
      }

      // Count binding violations (simplified - sessions without binding hash but used)
      if (session.used && !session.bindingHash) {
        bindingViolations++;
      }

      // Count security events (sessions with invalidation attempts)
      if (session.invalidationAttempts && session.invalidationAttempts > 0) {
        securityEvents++;
      }
    }

    const systemHealthy = replayAttempts < 10 && bindingViolations < 5;

    return {
      totalSessions,
      activeSessions,
      expiredSessions,
      compromisedSessions,
      replayAttempts,
      bindingViolations,
      securityEvents,
      timestamp: currentTime,
      systemHealthy
    };

  } catch (error) {
    logger.error(
      'Failed to get session security statistics',
      error instanceof Error ? error : new Error(String(error)),
      {
        service: 'sessionStatsService',
        function: 'getSessionSecurityStats'
      }
    );
    return {
      totalSessions: 0,
      activeSessions: 0,
      expiredSessions: 0,
      compromisedSessions: 0,
      replayAttempts: 0,
      bindingViolations: 0,
      securityEvents: 0,
      timestamp: new Date(),
      systemHealthy: false
    };
  }
}