import { PrismaClient } from '@prisma/client';
import { logger } from './logger';
import { config } from '../config';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

// Configure Prisma logging based on environment
const getPrismaLogConfig = (): string[] => {
  const baseLogs: string[] = ['error', 'warn'];

  // Add query logging for development
  if (config.server.env === 'development') {
    baseLogs.push('query');
  }

  // Add info logging for development and test
  if (config.server.env === 'development' || config.server.env === 'test') {
    baseLogs.push('info');
  }

  return baseLogs;
};

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: getPrismaLogConfig() as any,
    datasources: {
      db: {
        url: config.database.url,
      },
    },
  });

if (process.env.NODE_ENV !== 'production') {
  globalForPrisma.prisma = prisma;
}

// Log Prisma queries in development
if (process.env.NODE_ENV !== 'test') {
  (prisma.$on as any)('query', (e: any) => {
    logger.debug('Prisma Query', {
      query: e.query,
      params: e.params,
      duration: `${e.duration}ms`,
    });
  });

  (prisma.$on as any)('error', (e: any) => {
    logger.error('Prisma Error', {
      error: e.message,
    });
  });

  (prisma.$on as any)('info', (e: any) => {
    logger.info('Prisma Info', {
      message: e.message,
    });
  });

  (prisma.$on as any)('warn', (e: any) => {
    logger.warn('Prisma Warning', {
      message: e.message,
    });
  });
}

export const connectDB = async (): Promise<void> => {
  try {
    await prisma.$connect();

    // Environment-specific connection messages
    if (config.server.env === 'production') {
      logger.info('Production database connected successfully');
    } else if (config.server.env === 'test') {
      logger.info('Test database connected successfully');
    } else {
      logger.info(`Development database connected successfully (${config.database.url.split('@')[1] || 'local'})`);
    }
  } catch (error) {
    logger.error('Database connection failed', {
      error,
      environment: config.server.env,
      databaseUrl: config.server.env === 'production' ? '***masked***' : config.database.url
    });
    throw error;
  }
};

export const disconnectDB = async (): Promise<void> => {
  try {
    await prisma.$disconnect();

    // Environment-specific disconnection messages
    if (config.server.env === 'production') {
      logger.info('Production database disconnected successfully');
    } else {
      logger.info('Database disconnected successfully');
    }
  } catch (error) {
    logger.error('Database disconnection failed', { error });
    throw error;
  }
};

export const databaseService = {
  prisma,
  connectDB,
  disconnectDB,
  getStats: async () => {
    try {
      const [userCount, verificationCount, sessionCount, expiredSessions] = await Promise.all([
        prisma.adminVerification.count(),
        prisma.verificationHistory.count(),
        prisma.verificationSession.count({
          where: {
            expiresAt: {
              gt: new Date(),
            },
            used: false,
          },
        }),
        prisma.verificationSession.count({
          where: {
            expiresAt: {
              lt: new Date(),
            },
          },
        }),
      ]);

      return {
        users: userCount,
        verifications: verificationCount,
        activeSessions: sessionCount,
        expiredSessions,
      };
    } catch (error) {
      logger.error('Error getting database stats:', error);
      throw error;
    }
  },
  cleanupExpiredSessions: async () => {
    try {
      const result = await prisma.verificationSession.deleteMany({
        where: {
          expiresAt: {
            lt: new Date(),
          },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error cleaning up expired sessions:', error);
      throw error;
    }
  },
  cleanupOldHistory: async (retentionDays: number = 90) => {
    try {
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

      const result = await prisma.verificationHistory.deleteMany({
        where: {
          timestamp: {
            lt: cutoffDate,
          },
        },
      });
      return result.count;
    } catch (error) {
      logger.error('Error cleaning up old history:', error);
      throw error;
    }
  },
};

export default prisma;