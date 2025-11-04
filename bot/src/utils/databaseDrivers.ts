// Re-export the database driver classes
export { PrismaDatabaseDriver } from './drivers/prismaDriver';
export { JsonDatabaseDriver } from './drivers/jsonDriver';
export { SQLiteDatabaseDriver } from './drivers/sqliteDriver';

// Export the singleton instance
import { JsonDatabaseDriver } from './drivers/jsonDriver';
export const databaseDriver = new JsonDatabaseDriver();