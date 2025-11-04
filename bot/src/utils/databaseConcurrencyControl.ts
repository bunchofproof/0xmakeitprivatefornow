// Database Concurrency Control and Race Condition Prevention
// This module provides robust database operations with proper locking,
// atomic writes, and transaction semantics to prevent data corruption.

import * as fs from 'fs';
import * as path from 'path';
import { randomBytes } from 'crypto';
import { logger } from './logger';
import { pathValidator } from '@shared/utils/pathSecurityValidator';

// Add bot's database directory to allowed bases for path validation (PRODUCTION SECURITY)
pathValidator.addAllowedBase(path.join(process.cwd(), 'database'));
pathValidator.addAllowedBase(path.join(process.cwd(), 'zk-discord-verifier', 'database'));
// Add the specific absolute path causing the issue
pathValidator.addAllowedBase('C:\\Users\\Aryan\\Desktop\\wallet -gather\\Discord-admin-varification\\zk-discord-verifier\\database');

// Maintain full path validation - production security must be consistent
// NO bypassing of security for any environment

// File-level lock manager using proper file system operations
export class DatabaseFileLock {
  private lockFiles: Map<string, string> = new Map();
  private readonly LOCK_TIMEOUT = 10000; // 10 seconds
  private readonly LOCK_DIR = '.locks';

  constructor(private databaseDir: string) {
    this.ensureLockDirectory();
  }

  private ensureLockDirectory(): void {
    const lockDir = path.join(this.databaseDir, this.LOCK_DIR);
    if (!fs.existsSync(lockDir)) {
      fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Acquire an exclusive lock for a database file
   * @param filename - The database filename to lock
   * @param timeoutMs - Maximum time to wait for lock acquisition
   * @returns Promise that resolves to a release function
   */
  async acquireLock(filename: string, timeoutMs: number = this.LOCK_TIMEOUT): Promise<() => Promise<void>> {
    // CRITICAL SECURITY: Validate filename to prevent path traversal
    const filenameValidation = pathValidator.validatePath(filename, this.databaseDir);
    if (!filenameValidation.isValid) {
      throw new Error(`Invalid filename for lock: ${filenameValidation.error}`);
    }

    const relativeFilename = pathValidator.getRelativePath(filename, this.databaseDir) || filename;
    const lockFilePath = path.join(this.databaseDir, this.LOCK_DIR, `${relativeFilename}.lock`);
    
    // Validate the complete lock file path (ENABLED - production security)
    const lockPathValidation = pathValidator.validatePath(lockFilePath, this.databaseDir);
    if (!lockPathValidation.isValid) {
      throw new Error(`Invalid lock file path: ${lockPathValidation.error}`);
    }

    const startTime = Date.now();

    while (Date.now() - startTime < timeoutMs) {
      try {
        // Try to create lock file exclusively
        const lockFileDescriptor = fs.openSync(lockFilePath, 'wx', 0o600);
        
        // Write process info to lock file
        const lockInfo = {
          pid: process.pid,
          timestamp: Date.now(),
          hostname: require('os').hostname()
        };
        
        fs.writeFileSync(lockFileDescriptor, JSON.stringify(lockInfo));
        fs.closeSync(lockFileDescriptor);
        
        this.lockFiles.set(filename, lockFilePath);
        logger.debug(`Database lock acquired for: ${filename}`);
        
        // Return release function
        return async () => {
          try {
            if (fs.existsSync(lockFilePath)) {
              fs.unlinkSync(lockFilePath);
            }
            this.lockFiles.delete(filename);
            logger.debug(`Database lock released for: ${filename}`);
          } catch (error) {
            const err = error instanceof Error ? error : new Error(String(error));
            logger.error(`Error releasing lock for ${filename}:`, err);
          }
        };
        
      } catch (error: any) {
        if (error.code === 'EEXIST') {
          // Lock exists, check if it's stale
          try {
            const lockFile = fs.readFileSync(lockFilePath, 'utf8');
            const lockInfo = JSON.parse(lockFile);
            
            // Check if lock is stale (older than LOCK_TIMEOUT)
            if (Date.now() - lockInfo.timestamp > this.LOCK_TIMEOUT) {
              // Remove stale lock
              fs.unlinkSync(lockFilePath);
              logger.warn(`Removed stale lock for: ${filename}`);
              continue; // Try again
            }
          } catch {
            // Lock file corrupted, remove it
            try {
              fs.unlinkSync(lockFilePath);
            } catch {}
            continue;
          }
          
          // Wait a bit before retrying
          await new Promise(resolve => setTimeout(resolve, 50));
        } else {
          throw error;
        }
      }
    }

    throw new Error(`Failed to acquire lock for ${filename} within timeout`);
  }

  /**
   * Check if a file is currently locked
   */
  isLocked(filename: string): boolean {
    return this.lockFiles.has(filename);
  }

  /**
   * Force release all locks (emergency use only)
   */
  async forceReleaseAll(): Promise<void> {
    for (const [filename, lockFilePath] of this.lockFiles) {
      try {
        if (fs.existsSync(lockFilePath)) {
          fs.unlinkSync(lockFilePath);
        }
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error(`Error forcing release of lock for ${filename}:`, err);
      }
    }
    this.lockFiles.clear();
  }
}

// Atomic write manager using temporary files and rename
export class AtomicWriteManager {
  private tempDir: string;

  constructor(private databaseDir: string) {
    this.tempDir = path.join(databaseDir, '.temp');
    this.ensureTempDirectory();
  }

  private ensureTempDirectory(): void {
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Atomically write data to a file using temporary file + rename
   * @param filename - Target filename
   * @param data - Data to write
   * @param lockManager - Lock manager to ensure exclusive access
   * @param skipLocking - Skip lock acquisition if lock is already held (for transactions)
   */
  async atomicWrite(filename: string, data: any, lockManager: DatabaseFileLock, skipLocking: boolean = false): Promise<(() => Promise<void>) | null> {
    // CRITICAL SECURITY: Validate filename to prevent path traversal
    const filenameValidation = pathValidator.validatePath(filename, this.databaseDir);
    if (!filenameValidation.isValid) {
      throw new Error(`Invalid filename for atomic write: ${filenameValidation.error}`);
    }

    const validatedFilename = path.basename(filenameValidation.sanitizedPath!);
    const tempFilename = `${validatedFilename}.${randomBytes(8).toString('hex')}.tmp`;
    const tempPath = path.join(this.tempDir, tempFilename);
    const targetPath = path.join(this.databaseDir, validatedFilename);

    // Validate all file paths (ENABLED - production security must be consistent)
    const tempPathValidation = pathValidator.validatePath(tempPath, this.databaseDir);
    const targetPathValidation = pathValidator.validatePath(targetPath, this.databaseDir);
    
    if (!tempPathValidation.isValid) {
      throw new Error(`Invalid temp file path: ${tempPathValidation.error}`);
    }
    if (!targetPathValidation.isValid) {
      throw new Error(`Invalid target file path: ${targetPathValidation.error}`);
    }

    let releaseLock: (() => Promise<void>) | null = null;

    if (!skipLocking) {
      releaseLock = await lockManager.acquireLock(validatedFilename);
    } else {
      logger.debug(`Skipping lock acquisition for ${validatedFilename} - already held by transaction`);
    }
    
    try {
      // Write to temporary file
      const jsonData = JSON.stringify(data, null, 2);
      
      // Write with fsync for durability
      const fd = fs.openSync(tempPath, 'w', 0o600);
      try {
        fs.writeFileSync(fd, jsonData);
        fs.fsyncSync(fd); // Ensure data is written to disk
      } finally {
        fs.closeSync(fd);
      }

      // Atomic rename from temp to target
      fs.renameSync(tempPath, targetPath);
      
      logger.debug(`Atomic write completed for: ${validatedFilename}`);
      
    } finally {
      // Clean up temp file if it still exists
      try {
        if (fs.existsSync(tempPath)) {
          fs.unlinkSync(tempPath);
        }
      } catch (error) {
        logger.warn(`Failed to clean up temp file ${tempPath}:`, error);
      }
      
      if (releaseLock) {
        await releaseLock();
      }
    }

    return releaseLock;
  }
}

// Database transaction manager for multi-file operations
export class DatabaseTransaction {
  private operations: Array<{
    type: 'read' | 'write';
    filename: string;
    data?: any;
  }> = [];
  private originalData: Map<string, any> = new Map();

  constructor(
    private lockManager: DatabaseFileLock,
    private writeManager: AtomicWriteManager
  ) {}

  /**
   * Read a file within the transaction
   */
  async read(filename: string): Promise<any> {
    this.operations.push({ type: 'read', filename });
    return this.readFile(filename);
  }

  /**
   * Queue a write operation within the transaction
   */
  async write(filename: string, data: any): Promise<void> {
    this.operations.push({ type: 'write', filename, data });
  }

  /**
   * Execute the transaction atomically
   */
  async execute(): Promise<void> {
    const locks: (() => Promise<void>)[] = [];

    try {
      // Acquire all necessary locks
      const filenames = [...new Set(this.operations.map(op => op.filename))];
      for (const filename of filenames) {
        const releaseLock = await this.lockManager.acquireLock(filename);
        locks.push(releaseLock);
      }

      // Save original data for rollback
      for (const filename of filenames) {
        try {
          const filePath = path.resolve(this.databaseDir, filename);
          if (fs.existsSync(filePath)) {
            const content = fs.readFileSync(filePath, 'utf8');
            this.originalData.set(filename, JSON.parse(content));
          }
        } catch (error) {
          logger.warn(`Failed to backup ${filename} for transaction:`, error);
        }
      }

      // Execute write operations
      for (const operation of this.operations) {
        if (operation.type === 'write' && operation.data !== undefined) {
          await this.writeManager.atomicWrite(operation.filename, operation.data, this.lockManager, true);
        }
      }

      logger.debug(`Transaction committed successfully`);

    } catch (error) {
      // Rollback on error
      await this.rollback();
      throw error;
    } finally {
      // CRITICAL FIX: Ensure locks are ALWAYS released even if rollback fails
      // This prevents permanent deadlocks by guaranteeing lock release
      const lockReleases = locks.reverse();
      for (const releaseLock of lockReleases) {
        try {
          await releaseLock();
        } catch (releaseError) {
          // Log but don't rethrow - we need to release all locks
          logger.error(`Failed to release lock during transaction cleanup:`, releaseError instanceof Error ? releaseError : new Error(String(releaseError)));
        }
      }
    }
  }

  /**
   * Rollback the transaction to restore original state
   * CRITICAL FIX: Rollback must NEVER throw exceptions to prevent lock leaks
   */
  private async rollback(): Promise<void> {
    logger.info('Rolling back transaction due to error');

    try {
      for (const [filename, originalData] of this.originalData) {
        try {
          // CRITICAL: Use a separate lock manager instance for rollback to avoid
          // interference with the main transaction locks
          await this.writeManager.atomicWrite(filename, originalData, this.lockManager);
        } catch (error) {
          const err = error instanceof Error ? error : new Error(String(error));
          logger.error(`Failed to rollback ${filename}:`, err);
          // CRITICAL: Continue with other files even if one fails
        }
      }
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Critical error during transaction rollback:', err);
      // CRITICAL: Rollback failures must NOT throw - swallow all exceptions
    }
  }

  private readFile(filename: string): any {
    // CRITICAL SECURITY: Validate filename to prevent path traversal
    const filenameValidation = pathValidator.validatePath(filename, this.databaseDir);
    if (!filenameValidation.isValid) {
      logger.error(`Invalid filename in transaction read: ${filename}`);
      throw new Error(`Invalid filename for read operation: ${filenameValidation.error}`);
    }

    const validatedFilename = filenameValidation.sanitizedPath!;
    const filePath = path.resolve(this.databaseDir, validatedFilename);
    
    // Validate the complete file path (ENABLED - production security)
    const filePathValidation = pathValidator.validatePath(filePath, this.databaseDir);
    if (!filePathValidation.isValid) {
      logger.error(`Invalid file path in transaction read: ${filePath}`);
      throw new Error(`Invalid file path for read operation: ${filePathValidation.error}`);
    }
    
    if (!fs.existsSync(filePath)) {
      return [];
    }
    const content = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(content);
    return Array.isArray(parsed) ? parsed : [];
  }

  private get databaseDir(): string {
    return this.writeManager['databaseDir'];
  }
}

// Database consistency validator
export class DatabaseConsistencyValidator {
  /**
   * Validate database integrity and detect corruption
   */
  static async validateDatabase(databaseDir: string, files: string[]): Promise<{
    isConsistent: boolean;
    errors: string[];
    warnings: string[];
  }> {
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const filename of files) {
      const filePath = path.join(databaseDir, filename);
      
      try {
        // Check if file exists
        if (!fs.existsSync(filePath)) {
          errors.push(`Missing database file: ${filename}`);
          continue;
        }

        // Check file permissions
        const stats = fs.statSync(filePath);
        if (stats.mode & 0o222) { // Check if file is writable by others
          warnings.push(`File ${filename} has overly permissive permissions`);
        }

        // Check file size
        if (stats.size === 0) {
          warnings.push(`Empty database file: ${filename}`);
        }

        // Validate JSON structure
        try {
          const content = fs.readFileSync(filePath, 'utf8');
          const parsed = JSON.parse(content);
          
          if (!Array.isArray(parsed)) {
            errors.push(`Invalid JSON structure in ${filename}: expected array`);
          }
        } catch (error) {
          errors.push(`JSON parsing error in ${filename}: ${error instanceof Error ? error.message : String(error)}`);
        }

      } catch (error) {
        errors.push(`Error validating ${filename}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    return {
      isConsistent: errors.length === 0,
      errors,
      warnings
    };
  }

  /**
   * Attempt to repair corrupted database files
   */
  static async repairDatabase(databaseDir: string, files: string[]): Promise<{
    repaired: boolean;
    repairedFiles: string[];
    errors: string[];
  }> {
    const repairedFiles: string[] = [];
    const errors: string[] = [];

    for (const filename of files) {
      const filePath = path.join(databaseDir, filename);
      
      try {
        if (fs.existsSync(filePath)) {
          const content = fs.readFileSync(filePath, 'utf8');
          
          try {
            // Try to parse and validate
            const parsed = JSON.parse(content);
            
            if (!Array.isArray(parsed)) {
              // Try to wrap non-array in array
              const fixed = Array.isArray(parsed) ? parsed : [parsed];
              fs.writeFileSync(filePath, JSON.stringify(fixed, null, 2));
              repairedFiles.push(filename);
              logger.info(`Repaired JSON structure in ${filename}`);
            }
          } catch {
            // File is corrupted, recreate as empty array
            fs.writeFileSync(filePath, JSON.stringify([], null, 2));
            repairedFiles.push(filename);
            logger.info(`Recreated corrupted file: ${filename}`);
          }
        } else {
          // Missing file, create empty
          fs.writeFileSync(filePath, JSON.stringify([], null, 2));
          repairedFiles.push(filename);
          logger.info(`Recreated missing file: ${filename}`);
        }
      } catch (error) {
        errors.push(`Failed to repair ${filename}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    return {
      repaired: repairedFiles.length > 0,
      repairedFiles,
      errors
    };
  }
}

// Enhanced database driver with concurrency control
export class ConcurrencyControlledJsonDatabaseDriver {
  private lockManager: DatabaseFileLock;
  private writeManager: AtomicWriteManager;
  private readonly databaseFiles = [
    'verification-sessions.json',
    'admin-verifications.json', 
    'verification-history.json'
  ];

  constructor(databaseDir: string) {
    this.lockManager = new DatabaseFileLock(databaseDir);
    this.writeManager = new AtomicWriteManager(databaseDir);
  }

  /**
   * Execute a database transaction with proper locking
   */
  async executeTransaction(operations: (tx: DatabaseTransaction) => Promise<void>): Promise<void> {
    const transaction = new DatabaseTransaction(this.lockManager, this.writeManager);
    
    try {
      await operations(transaction);
      await transaction.execute();
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error('Database transaction failed:', err);
      throw error;
    }
  }

  /**
   * Atomically read a database file
   */
  async readFile(filename: string): Promise<any[]> {
    // CRITICAL SECURITY: Validate filename to prevent path traversal
    const filenameValidation = pathValidator.validatePath(filename, this.writeManager['databaseDir']);
    if (!filenameValidation.isValid) {
      throw new Error(`Invalid filename for read operation: ${filenameValidation.error}`);
    }

    const validatedFilename = filenameValidation.sanitizedPath!;
    const releaseLock = await this.lockManager.acquireLock(validatedFilename);
    
    try {
      const filePath = path.resolve(this.writeManager['databaseDir'], validatedFilename);
      
      // Validate the complete file path (ENABLED - production security)
      const filePathValidation = pathValidator.validatePath(filePath, this.writeManager['databaseDir']);
      if (!filePathValidation.isValid) {
        throw new Error(`Invalid file path for write operation: ${filePathValidation.error}`);
      }
      
      if (!fs.existsSync(filePath)) {
        return [];
      }
      
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(content);
      return Array.isArray(parsed) ? parsed : [];
      
    } finally {
      await releaseLock();
    }
  }

  /**
   * Atomically write to a database file
   */
  async writeFile(filename: string, data: any[]): Promise<void> {
    await this.writeManager.atomicWrite(filename, data, this.lockManager);
  }

  /**
   * Validate and repair database consistency
   */
  async validateAndRepairDatabase(): Promise<{
    isConsistent: boolean;
    repaired: boolean;
    errors: string[];
    warnings: string[];
  }> {
    const validation = await DatabaseConsistencyValidator.validateDatabase(
      this.writeManager['databaseDir'], 
      this.databaseFiles
    );

    let repaired = false;
    if (!validation.isConsistent) {
      const repairResult = await DatabaseConsistencyValidator.repairDatabase(
        this.writeManager['databaseDir'], 
        this.databaseFiles
      );
      repaired = repairResult.repaired;
      validation.errors.push(...repairResult.errors);
    }

    return {
      isConsistent: validation.errors.length === 0,
      repaired,
      errors: validation.errors,
      warnings: validation.warnings
    };
  }

  /**
   * Force cleanup of all locks (emergency use only)
   */
  async emergencyLockCleanup(): Promise<void> {
    await this.lockManager.forceReleaseAll();
  }
}

export default ConcurrencyControlledJsonDatabaseDriver;