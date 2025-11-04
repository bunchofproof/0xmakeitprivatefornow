import { logger } from './logger';

/**
 * Bot-specific audit logger implementation
 * Replaces the backend audit logger for bot service
 */
export class BotAuditLogger {
  static logSecurityViolation(source: string, violation: string, details: Record<string, any> = {}): void {
    logger.warn('Security violation detected', {
      source,
      violation,
      details,
      timestamp: new Date().toISOString(),
      service: 'discord-bot'
    });
  }

  static logRoleChange(source: string, actor: string, action: string, target: string, details: Record<string, any> = {}): void {
    logger.info('Role change performed', {
      source,
      actor,
      action,
      target,
      details,
      timestamp: new Date().toISOString(),
      service: 'discord-bot'
    });
  }
}