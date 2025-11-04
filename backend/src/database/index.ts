// Database abstraction factory - handles switching between local JSON and SQLite storage

import { JsonDatabaseDriver } from './jsonDriver';
import { SQLiteDatabaseDriver } from './sqliteDriver';
import { PrismaDatabaseDriver } from './prismaDriver';
import { logger } from '../utils/logger';
import path from 'path';
import { config } from '../config';

if (process.env.NODE_ENV !== 'production') {
  logger.info(`Initializing ${config.databaseBackend.backend.toUpperCase()} database driver.`);
}

// This path MUST go from backend directory up to project root, then down to 'database'
const dbPath = path.resolve(__dirname, '..', '..', '..', 'database');
if (process.env.NODE_ENV !== 'production') {
  logger.info(`Database path resolved to: ${dbPath}`);
}

// Export the single, correct instance based on config
export const database = (() => {
  // If DATABASE_URL is set, use Prisma driver assuming it's for PostgreSQL
  if (process.env.DATABASE_URL) {
    logger.info('DATABASE_URL is set, using Prisma driver');
    return new PrismaDatabaseDriver();
  }

  switch (config.databaseBackend.backend) {
    case 'json':
      return new JsonDatabaseDriver(dbPath);
    case 'sqlite':
      const sqliteDriver = new SQLiteDatabaseDriver(path.join(dbPath, 'database.sqlite'));
      // Initialize the database schema
      sqliteDriver.initializeDatabase().catch(err => {
        logger.error('Failed to initialize SQLite database:', err);
        throw err;
      });
      return sqliteDriver;
    case 'prisma':
      logger.warn('DATABASE_URL not found, falling back to JSON driver for Prisma backend');
      return new JsonDatabaseDriver(dbPath);
    default:
      logger.warn(`Unknown database backend: ${config.databaseBackend.backend}, falling back to JSON driver`);
      return new JsonDatabaseDriver(dbPath);
  }
})();