import * as cron from 'node-cron';
import { Client } from 'discord.js';
import { config } from '../config';
import { logger } from './logger';
import { sessionManager } from './sessionManager';
import { cleanupConfig } from '@shared/config/verification';

let scheduledJobs: cron.ScheduledTask[] = [];
let client: Client;

export function initializeScheduler(discordClient: Client): void {
  client = discordClient;
  logger.info('Initializing verification scheduler...');

  // Schedule verification reminders
  scheduleVerificationReminders();

  // Schedule cleanup of expired sessions
  scheduleCleanupTasks();

  // Schedule production maintenance tasks
  if (cleanupConfig.sessionRetentionHours > 0) {
    scheduleProductionMaintenance();
  }

  logger.info('Scheduler initialized successfully');
}

export async function loadScheduledReminders(): Promise<void> {
  // TODO: Load scheduled reminders from database
  // This would include reminders that were scheduled but not sent due to bot downtime
  logger.info('Loading scheduled reminders from database...');
}

function scheduleVerificationReminders(): void {
  try {
    // Schedule weekly verification reminders (every Monday at 9 AM)
    const reminderJob = cron.schedule(config.bot.reminderSchedule, async () => {
      await sendVerificationReminders();
    }, {
      scheduled: false,
    });

    reminderJob.start();
    scheduledJobs.push(reminderJob);

    logger.info(`Scheduled verification reminders: ${config.bot.reminderSchedule}`);

    // Schedule daily check for users with expiring verifications
    const expiryJob = cron.schedule('0 10 * * *', async () => {
      await checkExpiringVerifications();
    }, {
      scheduled: false,
    });

    expiryJob.start();
    scheduledJobs.push(expiryJob);

    logger.info('Scheduled daily verification expiry checks');

  } catch (error) {
   logger.error('Error scheduling verification reminders:', error instanceof Error ? error : new Error(String(error)));
  }
}

function scheduleCleanupTasks(): void {
  try {
    // Schedule cleanup of expired sessions every hour
    const cleanupJob = cron.schedule('0 * * * *', async () => {
      await cleanupExpiredSessions();
    }, {
      scheduled: false,
    });

    cleanupJob.start();
    scheduledJobs.push(cleanupJob);

    logger.info('Scheduled hourly cleanup of expired sessions');

  } catch (error) {
   logger.error('Error scheduling cleanup tasks:', error instanceof Error ? error : new Error(String(error)));
  }
}

function scheduleProductionMaintenance(): void {
  try {
    // Schedule full maintenance cleanup daily at 2 AM
    const maintenanceJob = cron.schedule('0 2 * * *', async () => {
      logger.info('Starting scheduled production maintenance cleanup...');
      const result = await sessionManager.performFullMaintenance();

      logger.info(`Production maintenance complete: Sessions cleaned: ${result.sessionsCleaned}, Admin verifications deactivated: ${result.adminVerificationsDeactivated}, History cleaned: ${result.historyCleaned}`);

      if (result.errors.length > 0) {
        logger.warn('Maintenance errors:', result.errors);
      }
    }, {
      scheduled: false,
    });

    maintenanceJob.start();
    scheduledJobs.push(maintenanceJob);

    // Schedule session health monitoring every 6 hours
    const healthJob = cron.schedule('0 */6 * * *', async () => {
      try {
        const stats = await sessionManager.getSessionHealthStats();
        logger.info('Session health stats:', stats);

        // Alert if too many expired sessions
        const expiredRatio = stats.totalSessions > 0 ? stats.expiredSessions / stats.totalSessions : 0;
        if (expiredRatio > 0.5) {
          logger.warn(`High expired session ratio: ${expiredRatio.toFixed(2)} (${stats.expiredSessions}/${stats.totalSessions})`);
        }

        // Alert if too many expired admin verifications
        const expiredAdminRatio = stats.totalAdminVerifications > 0 ? stats.expiredAdminVerifications / stats.totalAdminVerifications : 0;
        if (expiredAdminRatio > 0.2) {
          logger.warn(`High expired admin verification ratio: ${expiredAdminRatio.toFixed(2)} (${stats.expiredAdminVerifications}/${stats.totalAdminVerifications})`);
        }
      } catch (error) {
       logger.error('Error during health monitoring:', error instanceof Error ? error : new Error(String(error)));
      }
    }, {
      scheduled: false,
    });

    healthJob.start();
    scheduledJobs.push(healthJob);

    logger.info('Scheduled production maintenance tasks');

  } catch (error) {
   logger.error('Error scheduling production maintenance:', error instanceof Error ? error : new Error(String(error)));
  }
}

async function sendVerificationReminders(): Promise<void> {
  try {
    logger.info('Sending verification reminders...');

    // TODO: Query database for users who need reminders
    // This could include:
    // - Users who started verification but didn't complete it
    // - Users whose verification is expiring soon
    // - Users who haven't verified in a while

    // For now, this is a placeholder implementation
    logger.info('Verification reminders sent (placeholder implementation)');

  } catch (error) {
   logger.error('Error sending verification reminders:', error instanceof Error ? error : new Error(String(error)));
  }
}

async function checkExpiringVerifications(): Promise<void> {
  try {
    logger.info('Checking for expiring verifications...');

    // TODO: Query database for users whose verification expires in the next 7 days
    // Send them a reminder via DM

    // For now, this is a placeholder implementation
    logger.info('Expiring verification check completed (placeholder implementation)');

  } catch (error) {
   logger.error('Error checking expiring verifications:', error instanceof Error ? error : new Error(String(error)));
  }
}

async function cleanupExpiredSessions(): Promise<void> {
  try {
    logger.debug('Cleaning up expired verification sessions...');

    // TODO: Query database for expired sessions and mark them as expired
    // Also clean up old verification history records

    // For now, this is a placeholder implementation
    logger.debug('Expired session cleanup completed (placeholder implementation)');

  } catch (error) {
   logger.error('Error cleaning up expired sessions:', error instanceof Error ? error : new Error(String(error)));
  }
}

/**
 * Send a verification reminder to a specific user
 */
export async function sendUserReminder(
  discordUserId: string,
  reminderType: 'verification_reminder' | 'admin_review' = 'verification_reminder'
): Promise<boolean> {
  try {
    if (!client) {
      logger.error('Discord client not initialized');
      return false;
    }

    const user = await client.users.fetch(discordUserId);
    if (!user) {
      logger.warn(`User ${discordUserId} not found`);
      return false;
    }

    let message: string;
    if (reminderType === 'verification_reminder') {
      message = '🔐 Your ZKPassport verification link is still active! Use `/verify` to get a new link if needed.';
    } else {
      message = '📋 Your verification is pending admin review. Please be patient while we process your request.';
    }

    await user.send(message);
    logger.info(`Sent ${reminderType} to user ${discordUserId}`);

    return true;
  } catch (error) {
   logger.error(`Failed to send reminder to user ${discordUserId}:`, error instanceof Error ? error : new Error(String(error)));
   return false;
  }
}

/**
 * Stop all scheduled jobs (for graceful shutdown)
 */
export function stopScheduler(): void {
  logger.info('Stopping scheduler...');

  scheduledJobs.forEach(job => {
    job.stop();
  });

  scheduledJobs = [];
  logger.info('Scheduler stopped');
}