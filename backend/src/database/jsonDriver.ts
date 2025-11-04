// JSON-based local database driver for development and testing

import crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  DatabaseOperations,
  VerificationSession,
  AdminVerification,
  VerificationHistory
} from './interfaces';
import { logger } from '../utils/logger';

// Use the shared database lock manager for cross-process concurrency control
import { DatabaseLockManager, LockType } from '@shared/utils/databaseLockManager';

export class JsonDatabaseDriver implements DatabaseOperations {
  private dbPath: string;
  private lockManager: DatabaseLockManager;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
    this.lockManager = new DatabaseLockManager(dbPath);
  }

  private readJsonFile<T>(filename: string): T[] {
    try {
      const filePath = path.join(this.dbPath, filename);
      if (!fs.existsSync(filePath)) {
        // Create file with empty array if it doesn't exist
        fs.writeFileSync(filePath, JSON.stringify([], null, 2));
        return [];
      }
      const data = fs.readFileSync(filePath, 'utf8');
      return JSON.parse(data);
    } catch (error) {
      logger.error(`Error reading JSON file ${filename}:`, error);
      return [];
    }
  }

  private async writeJsonFile<T>(filename: string, data: T[]): Promise<void> {
    try {
      await this.lockManager.atomicWrite(filename, data);
    } catch (error) {
      logger.error(`Error writing JSON file ${filename}:`, error);
      throw error;
    }
  }

  async findVerificationSession(id: string): Promise<VerificationSession | null> {
    if (process.env.NODE_ENV !== 'production') {
      logger.debug(`findVerificationSession called with id: ${id}`);
    }
    logger.debug(`JSON DB: Finding verification session ${id}`);
    const sessions = this.readJsonFile<VerificationSession>('verification-sessions.json');
    if (process.env.NODE_ENV !== 'production') {
      logger.debug(`Total sessions in file: ${sessions.length}`);
    }

    // Parse dates back to Date objects
    const session = sessions.find(s => s.id === id);
    if (process.env.NODE_ENV !== 'production') {
      logger.debug(`Session found:`, session ? { id: session.id, discordUserId: session.discordUserId } : null);
    }

    if (session) {
      const parsedSession = {
        ...session,
        expiresAt: new Date(session.expiresAt),
        createdAt: new Date(session.createdAt)
      };
      if (process.env.NODE_ENV !== 'production') {
        logger.debug(`Returning parsed session for user: ${parsedSession.discordUserId}`);
      }
      return parsedSession;
    }

    if (process.env.NODE_ENV !== 'production') {
      logger.debug(`No session found for id: ${id}, returning null`);
    }
    return null;
  }

  async findVerificationSession_DEBUG(id: string): Promise<VerificationSession | null> {
    if (process.env.NODE_ENV !== 'production') {
      logger.debug('findVerificationSession called with id:', id);
    }
    const result = await this.findVerificationSession(id);
    if (process.env.NODE_ENV !== 'production') {
      logger.debug('findVerificationSession result:', result);
    }
    return result;
  }

  async createVerificationSession(session: Omit<VerificationSession, 'createdAt'>): Promise<VerificationSession> {
    logger.debug(`JSON DB: Creating verification session ${session.id}`);
    const sessions = this.readJsonFile<VerificationSession>('verification-sessions.json');

    const newSession: VerificationSession = {
      ...session,
      createdAt: new Date()
    };

    sessions.push(newSession);
    await this.writeJsonFile('verification-sessions.json', sessions);

    return newSession;
  }

  async updateVerificationSession(id: string, updates: Partial<VerificationSession>): Promise<VerificationSession | null> {
    logger.debug(`JSON DB: Updating verification session ${id}`);
    const sessions = this.readJsonFile<VerificationSession>('verification-sessions.json');

    const index = sessions.findIndex(s => s.id === id);
    if (index === -1) return null;

    sessions[index] = { ...sessions[index], ...updates };
    await this.writeJsonFile('verification-sessions.json', sessions);

    // Parse dates back to Date objects
    return {
      ...sessions[index],
      expiresAt: new Date(sessions[index].expiresAt),
      createdAt: new Date(sessions[index].createdAt)
    };
  }

  async markSessionAsUsed(id: string): Promise<boolean> {
    logger.info(`Session ${id} invalidated for security - marking as used`);
    return !!(await this.updateVerificationSession(id, { used: true }));
  }

  async findAdminVerification(discordUserId: string): Promise<AdminVerification | null> {
    logger.debug(`JSON DB: Finding admin verification for ${discordUserId}`);
    const verifications = this.readJsonFile<AdminVerification>('admin-verifications.json');

    const verification = verifications.find(v => v.discordUserId === discordUserId);
    if (verification) {
      return {
        ...verification,
        passportFingerprint: verification.passportFingerprint || '',
        lastVerified: new Date(verification.lastVerified),
        createdAt: new Date(verification.createdAt)
      };
    }
    return null;
  }

  async findVerificationByUniqueIdentifier(uniqueIdentifier: string): Promise<AdminVerification | null> {
    logger.debug(`JSON DB: Finding verification by unique identifier ${uniqueIdentifier}`);
    const verifications = this.readJsonFile<AdminVerification>('admin-verifications.json');

    const verification = verifications.find(v => v.uniqueIdentifier === uniqueIdentifier);
    if (verification) {
      return {
        ...verification,
        passportFingerprint: verification.passportFingerprint || '',
        lastVerified: new Date(verification.lastVerified),
        createdAt: new Date(verification.createdAt)
      };
    }
    return null;
  }

  async findVerificationByFingerprint(passportFingerprint: string): Promise<AdminVerification | null> {
    logger.debug(`JSON DB: Finding verification by passport fingerprint ${passportFingerprint}`);
    const verifications = this.readJsonFile<AdminVerification>('admin-verifications.json');

    const verification = verifications.find(v => v.passportFingerprint === passportFingerprint);
    if (verification) {
      return {
        ...verification,
        passportFingerprint: verification.passportFingerprint || '',
        lastVerified: new Date(verification.lastVerified),
        createdAt: new Date(verification.createdAt)
      };
    }
    return null;
  }

  async upsertAdminVerification(verification: Omit<AdminVerification, 'createdAt'>): Promise<AdminVerification> {
    logger.debug(`JSON DB: Upserting admin verification for ${verification.discordUserId}`);
    const verifications = this.readJsonFile<AdminVerification>('admin-verifications.json');

    const index = verifications.findIndex(v => v.discordUserId === verification.discordUserId);

    const newVerification: AdminVerification = {
      ...verification,
      createdAt: index >= 0 ? verifications[index].createdAt : new Date()
    };

    if (index >= 0) {
      verifications[index] = newVerification;
    } else {
      verifications.push(newVerification);
    }

    await this.writeJsonFile('admin-verifications.json', verifications);

    // Parse date back to Date object
    return {
      ...newVerification,
      lastVerified: new Date(newVerification.lastVerified),
      createdAt: new Date(newVerification.createdAt)
    };
  }

  async createVerificationHistory(history: Omit<VerificationHistory, 'id' | 'createdAt'>): Promise<VerificationHistory> {
    logger.debug(`JSON DB: Creating verification history for ${history.discordUserId}`);
    const histories = this.readJsonFile<VerificationHistory>('verification-history.json');

    const newHistory: VerificationHistory = {
      ...history,
      id: crypto.randomUUID(),
      createdAt: new Date()
    };

    histories.push(newHistory);
    await this.writeJsonFile('verification-history.json', histories);

    return newHistory;
  }

  async healthCheck(): Promise<boolean> {
    try {
      // Test basic file operations
      this.readJsonFile<VerificationSession>('verification-sessions.json');
      return true;
    } catch (error) {
      logger.error('JSON DB health check failed:', error);
      return false;
    }
  }

  /**
   * Execute a database transaction - enables unified transactions for the entire verification process
   */
  async executeTransaction<T = any>(
    resourceNames: string[],
    transactionFn: (tx: any) => Promise<T>
  ): Promise<T> {
    // Delegate to the lock manager's executeTransaction method and extract the data
    const result = await this.lockManager.executeTransaction(resourceNames, transactionFn);
    
    // Handle transaction result
    if (result.success) {
      return result.data!;
    } else {
      // Re-throw the original error or create a generic one
      throw result.error || new Error('Transaction failed');
    }
  }
}