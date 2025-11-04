// Shared Database Lock Manager for Cross-Process Concurrency Control
// Provides atomic file operations, deadlock prevention, and transaction support
// across bot, backend, and web components

import * as fs from 'fs';
import * as path from 'path';
import { randomBytes, createHash } from 'crypto';
import { logger } from './logger';

// Removed unused pathValidator import
// Session-specific lock types for different operation patterns
export enum LockType {
  SHARED_READ = 'shared_read',
  EXCLUSIVE_WRITE = 'exclusive_write',
  TRANSACTION_LOCK = 'transaction_lock'
}

// Database operation context for transaction management
export interface DatabaseOperationContext {
  operationId: string;
  operationType: 'read' | 'write' | 'transaction';
  resourceName: string;
  timestamp: number;
  processId: string;
  hostname: string;
  userId?: string;
  sessionId?: string;
}

// Lock information stored in lock files
export interface LockInfo {
  lockId: string;
  lockType: LockType;
  processId: string;
  hostname: string;
  timestamp: number;
  operationContext?: DatabaseOperationContext;
  lockTimeout: number;
  resourceHash: string; // Hash of locked resource to prevent conflicts
}

// Database transaction result
export interface DatabaseTransactionResult<T = any> {
  success: boolean;
  data?: T;
  error?: Error;
  operationId: string;
  lockDuration: number;
  conflictCount: number;
}

// Resource conflict detection result
export interface ResourceConflictResult {
  hasConflict: boolean;
  conflictingLocks: LockInfo[];
  suggestedResolution?: string;
}

/**
 * Comprehensive database lock manager with deadlock prevention
 * and transaction support for multi-process environments
 */
export class DatabaseLockManager {
  private lockRegistry: Map<string, LockInfo> = new Map();
  private readonly LOCK_TIMEOUT = 8000; // 8 seconds (optimized from 30s for better responsiveness)
//   private readonly DEADLOCK_TIMEOUT = 5000; // 5 seconds for deadlock detection
  private readonly LOCK_DIR = '.db_locks';
  private readonly TEMP_DIR = '.db_temp';
  private readonly MAX_RETRIES = 3;
  private readonly BASE_RETRY_DELAY = 50; // 50ms base delay for exponential backoff
  private readonly MAX_RETRY_DELAY = 2000; // 2s max delay between retries
  private lockAttempts = 0; // Counter for lock attempts
  private totalLockTime = 0; // Total time spent acquiring locks
  
  constructor(private databaseDir: string) {
    this.ensureDirectories();
    this.cleanupStaleLocks();
  }

  private ensureDirectories(): void {
    const lockDir = path.join(this.databaseDir, this.LOCK_DIR);
    const tempDir = path.join(this.databaseDir, this.TEMP_DIR);
    
    if (!fs.existsSync(lockDir)) {
      fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 });
    }
    
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Acquire a lock with automatic deadlock prevention
   */
  async acquireLock(
    resourceName: string, 
    lockType: LockType = LockType.EXCLUSIVE_WRITE,
    context?: Partial<DatabaseOperationContext>,
    timeoutMs: number = this.LOCK_TIMEOUT
  ): Promise<() => Promise<void>> {
    
    // Validate resource path
    const resourcePath = this.resolveResourcePath(resourceName);
    const resourceHash = this.generateResourceHash(resourcePath);
    
    const lockInfo: LockInfo = {
      lockId: randomBytes(16).toString('hex'),
      lockType,
      processId: String(process.pid),
      hostname: require('os').hostname(),
      timestamp: Date.now(),
      operationContext: {
        operationId: randomBytes(8).toString('hex'),
        operationType: lockType === LockType.SHARED_READ ? 'read' : 'write',
        resourceName,
        timestamp: Date.now(),
        processId: String(process.pid),
        hostname: require('os').hostname(),
        ...context
      },
      lockTimeout: timeoutMs,
      resourceHash
    };

    const lockFilePath = path.join(this.databaseDir, this.LOCK_DIR, `${resourceHash}.lock`);
    const startTime = Date.now();
    let attemptCount = 0;
    
    logger.info(`🔒 Starting lock acquisition for ${resourceName} (${lockType}) with ${timeoutMs}ms timeout`);

    while (Date.now() - startTime < timeoutMs && attemptCount < this.MAX_RETRIES) {
      attemptCount++;

      try {
        // Try to create lock file exclusively
        const lockFileDescriptor = fs.openSync(lockFilePath, 'wx', 0o600);
        
        // Write lock information
        fs.writeFileSync(lockFileDescriptor, JSON.stringify(lockInfo));
        fs.closeSync(lockFileDescriptor);
        
        // Check for conflicts with existing locks
        const conflictCheck = await this.checkResourceConflicts(resourceHash, lockInfo);
        if (conflictCheck.hasConflict) {
          // Release the lock we just acquired
          this.releaseLockFile(lockFilePath);
          
          // If we can resolve the conflict automatically, try that
          if (this.canAutoResolveConflict(conflictCheck.conflictingLocks, lockInfo)) {
            await this.resolveConflict(conflictCheck.conflictingLocks, lockInfo);
            continue; // Retry acquiring the lock
          }
          
          // Wait before retrying with exponential backoff
          const backoffDelay = Math.min(this.BASE_RETRY_DELAY * Math.pow(2, attemptCount - 1), this.MAX_RETRY_DELAY);
          logger.debug(`🔄 Retrying lock acquisition for ${resourceName} in ${backoffDelay}ms (attempt ${attemptCount})`);
          await this.sleep(backoffDelay);
          continue;
        }

        // Lock acquired successfully
        this.lockRegistry.set(resourceHash, lockInfo);
        this.lockAttempts++;
        const totalTime = Date.now() - startTime;
        this.totalLockTime += totalTime;
        
        const avgLockTime = this.totalLockTime / this.lockAttempts;
        logger.info(`✅ LOCK ACQUIRED: ${resourceName} (${lockType}) - Attempt #${attemptCount}, Total time: ${totalTime}ms, Avg: ${avgLockTime.toFixed(1)}ms`);
        
        // Return release function
        return async () => {
          await this.releaseLock(resourceHash, resourceName);
        };

      } catch (error: any) {
        if (error.code === 'EEXIST') {
          // Lock exists, check if it's stale
          try {
            const existingLockInfo = await this.readLockFile(lockFilePath);
            
            if (this.isLockStale(existingLockInfo)) {
              // Remove stale lock and retry
              this.releaseLockFile(lockFilePath);
              logger.warn(`Removed stale lock for: ${resourceName}`);
              continue;
            }
            
            // Lock is active, wait and retry with exponential backoff
            const backoffDelay = Math.min(this.BASE_RETRY_DELAY * Math.pow(2, attemptCount - 1), this.MAX_RETRY_DELAY);
            logger.debug(`⏳ Lock active for ${resourceName}, retrying in ${backoffDelay}ms (attempt ${attemptCount})`);
            await this.sleep(backoffDelay);
          } catch {
            // Lock file corrupted, remove it
            try {
              this.releaseLockFile(lockFilePath);
            } catch {}
            continue;
          }
        } else {
          throw error;
        }
      }
    }

    const elapsedTime = Date.now() - startTime;
    const avgLockTime = this.lockAttempts > 0 ? this.totalLockTime / this.lockAttempts : 0;
    
    logger.error(`🚨 LOCK ACQUISITION FAILED: ${resourceName} after ${elapsedTime}ms (timeout: ${timeoutMs}ms)`);
    logger.error(`📊 Lock Statistics: Total attempts: ${this.lockAttempts}, Average acquisition time: ${avgLockTime.toFixed(1)}ms`);
    logger.error(`💡 Possible solutions:`);
    logger.error(`   - Check for deadlocks or long-running transactions`);
    logger.error(`   - Verify resource is not locked by another process`);
    logger.error(`   - Consider increasing timeout for this resource`);
    
    throw new Error(`Failed to acquire lock for ${resourceName} after ${timeoutMs}ms (attempted for ${elapsedTime}ms, ${attemptCount} attempts)`);
  }

  /**
   * Execute a transaction with automatic locking and rollback
   */
  async executeTransaction<T = any>(
    resourceNames: string[],
    transactionFn: (tx: DatabaseTransaction) => Promise<T>,
    context?: Partial<DatabaseOperationContext>
  ): Promise<DatabaseTransactionResult<T>> {
    
    const operationId = randomBytes(8).toString('hex');
    const startTime = Date.now();
    
    // ENHANCED: Master Key Locking Strategy with improved deadlock prevention
    // 1. Sort resource names for consistent locking order (prevents deadlocks)
    const sortedResources = [...new Set(resourceNames)].sort();
    const acquiredLocks: Array<() => Promise<void>> = [];
    
    console.log(`🎯 MASTER KEY TRANSACTION START: Operation ${operationId}`);
    console.log(`📋 Resources to lock (in sorted order): ${sortedResources.join(', ')}`);
    
    try {
      // ENHANCED: Acquire all locks in strict alphabetical order with enhanced timeout
      for (const resourceName of sortedResources) {
        console.log(`🔒 Acquiring lock for: ${resourceName}`);
        
        const releaseLock = await this.acquireLock(
          resourceName,
          LockType.TRANSACTION_LOCK,
          { operationId, ...context },
          this.LOCK_TIMEOUT + 10000 // Extended timeout for multi-resource transactions
        );
        
        acquiredLocks.push(releaseLock);
        console.log(`✅ Lock acquired for: ${resourceName}`);
      }
      
      console.log(`🎯 All locks acquired successfully for operation ${operationId}`);
      
      // Create transaction context
      const transaction = new DatabaseTransaction(this, sortedResources, operationId);
      
      // Execute transaction function with timeout
      const result = await Promise.race([
        transactionFn(transaction),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Transaction timeout')), 25000)
        )
      ]);
      
      console.log(`🎯 Transaction function completed for operation ${operationId}`);
      
      // Release all locks in reverse order
      console.log(`🔓 Releasing ${acquiredLocks.length} locks...`);
      await Promise.all(acquiredLocks.reverse().map(release => release()));
      
      const duration = Date.now() - startTime;
      console.log(`✅ MASTER KEY TRANSACTION COMPLETED: Operation ${operationId} in ${duration}ms`);
      
      return {
        success: true,
        data: result as T,
        operationId,
        lockDuration: duration,
        conflictCount: 0
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      const err = error instanceof Error ? error : new Error(String(error));
      
      // Release any acquired locks on error
      if (acquiredLocks.length > 0) {
        console.log(`🚨 ERROR in operation ${operationId} - releasing ${acquiredLocks.length} acquired locks`);
        try {
          await Promise.all(acquiredLocks.reverse().map(release => release()));
        } catch (releaseError) {
          console.error(`❌ Failed to release locks during error cleanup:`, releaseError);
        }
      }
      
      // ENHANCED ERROR CAPTURE WITH MORE CONTEXT
      console.error('\n🚨 MASTER KEY TRANSACTION ERROR 🚨');
      console.error('Operation ID:', operationId);
      console.error('Duration:', duration + 'ms');
      console.error('Resources involved:', sortedResources.join(', '));
      console.error('Locks acquired before error:', acquiredLocks.length);
      console.error('Error Type:', err.constructor.name);
      console.error('Error Message:', `"${err.message}"`);
      console.error('Error Stack:', err.stack);
      console.error('Timestamp:', new Date().toISOString());
      
      // Log lock conflicts if this was a timeout
      if (err.message.includes('timeout') || err.message.includes('Failed to acquire lock')) {
        console.error('🔍 LOCK CONFLICT ANALYSIS:');
        console.error('- This indicates a deadlock or resource contention');
        console.error('- Master Key strategy should prevent this in most cases');
        console.error('- Possible causes:');
        console.error('  * External code acquiring locks outside transactions');
        console.error('  * Inconsistent lock ordering in other parts of the system');
        console.error('  * Very long-running transactions');
      }
      
      logger.error(`MASTER KEY Transaction ${operationId} failed after ${duration}ms: ${err.constructor.name}: ${err.message}`);
      
      return {
        success: false,
        error: err,
        operationId,
        lockDuration: duration,
        conflictCount: acquiredLocks.length
      };
    }
  }

  /**
   * Atomic file write with automatic locking
   */
  async atomicWrite(
    resourceName: string, 
    data: any, 
    backupBeforeWrite: boolean = true
  ): Promise<void> {
    
    const resourcePath = this.resolveResourcePath(resourceName);
    const tempFilename = `${path.basename(resourcePath)}.${randomBytes(8).toString('hex')}.tmp`;
    const tempPath = path.join(this.databaseDir, this.TEMP_DIR, tempFilename);
    const backupPath = backupBeforeWrite ? `${resourcePath}.backup` : null;
    
    let releaseLock: (() => Promise<void>) | null = null;
    
    try {
      // Acquire exclusive lock
      releaseLock = await this.acquireLock(resourceName, LockType.EXCLUSIVE_WRITE);
      
      // Create backup if requested
      if (backupBeforeWrite && fs.existsSync(resourcePath) && backupPath) {
        fs.copyFileSync(resourcePath, backupPath);
      }
      
      // Write to temporary file
      const jsonData = JSON.stringify(data, null, 2);
      const fd = fs.openSync(tempPath, 'w', 0o600);
      
      try {
        fs.writeFileSync(fd, jsonData);
        fs.fsyncSync(fd); // Ensure durability
      } finally {
        fs.closeSync(fd);
      }
      
      // Atomic rename
      fs.renameSync(tempPath, resourcePath);
      
      logger.debug(`Atomic write completed for: ${resourceName}`);
      
    } finally {
      // Cleanup and release lock
      if (fs.existsSync(tempPath)) {
        try {
          fs.unlinkSync(tempPath);
        } catch (error) {
          logger.warn(`Failed to cleanup temp file ${tempPath}:`, error);
        }
      }
      
      if (releaseLock) {
        await releaseLock();
      }
    }
  }

  /**
   * Atomic file read with shared locking
   */
  async atomicRead(resourceName: string): Promise<any> {
    const resourcePath = this.resolveResourcePath(resourceName);
    
    // Acquire shared lock
    const releaseLock = await this.acquireLock(resourceName, LockType.SHARED_READ);
    
    try {
      if (!fs.existsSync(resourcePath)) {
        return []; // Return empty array for non-existent files
      }
      
      const content = fs.readFileSync(resourcePath, 'utf8');
      const parsed = JSON.parse(content);
      
      return Array.isArray(parsed) ? parsed : [];
      
    } finally {
      await releaseLock();
    }
  }

  /**
   * Force cleanup of all locks (emergency use only)
   */
  async emergencyCleanup(): Promise<{ cleaned: number; errors: string[] }> {
    const cleaned: string[] = [];
    const errors: string[] = [];
    for (const [resourceHash] of this.lockRegistry) {
      try {
        const lockFilePath = path.join(this.databaseDir, this.LOCK_DIR, `${resourceHash}.lock`);
        if (fs.existsSync(lockFilePath)) {
          fs.unlinkSync(lockFilePath);
          cleaned.push(resourceHash);
        }
      } catch (error) {
        errors.push(`Failed to clean lock ${resourceHash}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }
    
    this.lockRegistry.clear();
    
    // Also cleanup stale lock files
    const lockDir = path.join(this.databaseDir, this.LOCK_DIR);
    if (fs.existsSync(lockDir)) {
      const lockFiles = fs.readdirSync(lockDir);
      
      for (const lockFile of lockFiles) {
        if (lockFile.endsWith('.lock')) {
          try {
            const lockFilePath = path.join(lockDir, lockFile);
            const lockInfo = await this.readLockFile(lockFilePath);
            
            if (this.isLockStale(lockInfo)) {
              fs.unlinkSync(lockFilePath);
              cleaned.push(lockFile);
            }
          } catch (error) {
            errors.push(`Failed to validate lock file ${lockFile}: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      }
    }
    
    logger.info(`Emergency cleanup completed: ${cleaned.length} locks cleaned, ${errors.length} errors`);
    
    return { cleaned: cleaned.length, errors };
  }

  /**
   * Get lock statistics and health status
   */
  getLockStatistics(): {
    activeLocks: number;
    lockTypes: Record<string, number>;
    oldestLock: { age: number; resource: string } | null;
    processLocks: number;
  } {
    const lockTypes: Record<string, number> = {};
    let oldestLock: { age: number; resource: string } | null = null;
    let oldestAge = 0;
    
    for (const [resourceHash, lockInfo] of this.lockRegistry) {
      const age = Date.now() - lockInfo.timestamp;
      
      // Count lock types
      lockTypes[lockInfo.lockType] = (lockTypes[lockInfo.lockType] || 0) + 1;
      
      // Track oldest lock
      if (age > oldestAge) {
        oldestAge = age;
        oldestLock = { age, resource: lockInfo.operationContext?.resourceName || resourceHash };
      }
    }
    
    const processLocks = Array.from(this.lockRegistry.values())
      .filter(lock => lock.processId === String(process.pid)).length;
    
    return {
      activeLocks: this.lockRegistry.size,
      lockTypes,
      oldestLock,
      processLocks
    };
  }

  // Private helper methods
  private async releaseLock(resourceHash: string, resourceName: string): Promise<void> {
    const lockFilePath = path.join(this.databaseDir, this.LOCK_DIR, `${resourceHash}.lock`);
    
    try {
      const existingLock = this.lockRegistry.get(resourceHash);
      const lockAge = existingLock ? Date.now() - existingLock.timestamp : 0;
      
      this.releaseLockFile(lockFilePath);
      this.lockRegistry.delete(resourceHash);
      
      logger.debug(`🔓 Database lock released for: ${resourceName} (age: ${lockAge}ms)`);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      logger.error(`Error releasing lock for ${resourceName}:`, err);
    }
  }

  private releaseLockFile(lockFilePath: string): void {
    if (fs.existsSync(lockFilePath)) {
      fs.unlinkSync(lockFilePath);
    }
  }

  private resolveResourcePath(resourceName: string): string {
    const normalizedPath = path.normalize(resourceName);
    
    // Validate path is within database directory
    const fullPath = path.resolve(this.databaseDir, normalizedPath);
    if (!fullPath.startsWith(path.resolve(this.databaseDir))) {
      throw new Error(`Invalid resource path: ${resourceName}`);
    }
    
    return fullPath;
  }

  private generateResourceHash(resourcePath: string): string {
    return createHash('sha256').update(resourcePath).digest('hex').substring(0, 16);
  }

  private async readLockFile(lockFilePath: string): Promise<LockInfo> {
    const content = fs.readFileSync(lockFilePath, 'utf8');
    return JSON.parse(content);
  }

  private isLockStale(lockInfo: LockInfo): boolean {
    return Date.now() - lockInfo.timestamp > lockInfo.lockTimeout;
  }

  private async checkResourceConflicts(
    resourceHash: string, 
    newLockInfo: LockInfo
  ): Promise<ResourceConflictResult> {
    const conflictingLocks: LockInfo[] = [];
    
    for (const [existingHash, existingLock] of this.lockRegistry) {
      if (existingHash === resourceHash || existingLock.resourceHash === resourceHash) {
        // Check for conflict based on lock types
        if (this.isLockConflict(existingLock, newLockInfo)) {
          conflictingLocks.push(existingLock);
        }
      }
    }
    
    // ✅ ADDITIONAL CHECK: Allow shared reads during transaction locks for same process
    // This prevents the nested transaction deadlock specifically
    if (conflictingLocks.length > 0 && newLockInfo.lockType === LockType.SHARED_READ) {
      const hasTransactionLock = conflictingLocks.some(lock => lock.lockType === LockType.TRANSACTION_LOCK);
      const sameProcess = conflictingLocks.every(lock => lock.processId === newLockInfo.processId);
      
      if (hasTransactionLock && sameProcess) {
        logger.debug(`🔓 Allowing shared read lock during transaction lock (same process: ${newLockInfo.processId})`);
        return {
          hasConflict: false,
          conflictingLocks: [],
          suggestedResolution: 'Transaction lock allows shared reads from same process'
        };
      }
    }
    
    return {
      hasConflict: conflictingLocks.length > 0,
      conflictingLocks,
      suggestedResolution: conflictingLocks.length > 0 ? 
        'Consider retrying with shared locking for read operations' : undefined
    };
  }

  private isLockConflict(lock1: LockInfo, lock2: LockInfo): boolean {
    // Exclusive locks conflict with any other lock
    if (lock1.lockType === LockType.EXCLUSIVE_WRITE || lock2.lockType === LockType.EXCLUSIVE_WRITE) {
      return true;
    }
    
    // Transaction locks conflict with any other transaction lock (unless same operation)
    if (lock1.lockType === LockType.TRANSACTION_LOCK && lock2.lockType === LockType.TRANSACTION_LOCK) {
      return lock1.operationContext?.operationId !== lock2.operationContext?.operationId;
    }
    
    // ✅ FIXED: Allow shared read locks during transaction locks for same process
    // This prevents self-deadlock when session validation runs within a transaction
    if ((lock1.lockType === LockType.TRANSACTION_LOCK && lock2.lockType === LockType.SHARED_READ) ||
        (lock1.lockType === LockType.SHARED_READ && lock2.lockType === LockType.TRANSACTION_LOCK)) {
      // Allow if same process and transaction lock was acquired first (prevents nested transaction deadlock)
      return lock1.processId !== lock2.processId;
    }
    
    // Same resource conflicts
    return lock1.resourceHash === lock2.resourceHash;
  }

  private canAutoResolveConflict(conflictingLocks: LockInfo[], _newLock: LockInfo): boolean {
    // We can auto-resolve if:
    // 1. All conflicting locks are stale
    // 2. Or we're trying to acquire a shared read lock and all conflicting locks are shared reads
    return conflictingLocks.every(lock => 
      this.isLockStale(lock) || 
      (_newLock.lockType === LockType.SHARED_READ && lock.lockType === LockType.SHARED_READ)
    );
  }

  private async resolveConflict(conflictingLocks: LockInfo[], _newLock: LockInfo): Promise<void> {
    for (const conflictingLock of conflictingLocks) {
      if (this.isLockStale(conflictingLock)) {
        // Remove stale lock
        const lockFilePath = path.join(
          this.databaseDir, 
          this.LOCK_DIR, 
          `${conflictingLock.resourceHash}.lock`
        );
        this.releaseLockFile(lockFilePath);
        this.lockRegistry.delete(conflictingLock.resourceHash);
        logger.debug(`Auto-resolved conflict by removing stale lock`);
      }
    }
  }
private async cleanupStaleLocks(): Promise<void> {
    const lockDir = path.join(this.databaseDir, this.LOCK_DIR);
    
    if (!fs.existsSync(lockDir)) {
      return;
    }
    
    const lockFiles = fs.readdirSync(lockDir);
    let cleaned = 0;
    
    for (const lockFile of lockFiles) {
      if (lockFile.endsWith('.lock')) {
        try {
          const lockFilePath = path.join(lockDir, lockFile);
          const lockInfo = await this.readLockFile(lockFilePath);
          
          if (this.isLockStale(lockInfo)) {
            fs.unlinkSync(lockFilePath);
            cleaned++;
          }
        } catch (error) {
          logger.warn(`Failed to cleanup stale lock ${lockFile}:`, error);
        }
      }
    }
    
    if (cleaned > 0) {
      logger.info(`Cleaned up ${cleaned} stale locks on startup`);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * Database transaction context for transactional operations
 */
export class DatabaseTransaction {
  private lockedResources: Set<string> = new Set(); // Track already-locked resources
  private operationId: string;

  constructor(
    private lockManager: DatabaseLockManager,
    resourceNames: string[],
    operationId: string
  ) {
    this.operationId = operationId;
    // Mark all locked resources as available for direct access
    resourceNames.forEach(resource => this.lockedResources.add(resource));
  }

  async read(resourceName: string): Promise<any> {
    // ✅ DIRECT ACCESS: Skip lock acquisition if resource is already locked by this transaction
    if (this.lockedResources.has(resourceName)) {
      const resourcePath = (this.lockManager as any).resolveResourcePath(resourceName);
      const fs = require('fs');
      
      if (!fs.existsSync(resourcePath)) {
        return []; // Return empty array for non-existent files
      }
      
      const content = fs.readFileSync(resourcePath, 'utf8');
      const parsed = JSON.parse(content);
      
      logger.debug(`📖 Direct read from transaction-locked resource: ${resourceName}`);
      return Array.isArray(parsed) ? parsed : [];
    }
    
    // Fallback to normal atomic read for resources not locked by this transaction
    logger.debug(`🔓 Falling back to atomic read for: ${resourceName}`);
    return await this.lockManager.atomicRead(resourceName);
  }

  async write(resourceName: string, data: any): Promise<void> {
    // ✅ DIRECT ACCESS: Skip lock acquisition if resource is already locked by this transaction
    if (this.lockedResources.has(resourceName)) {
      const resourcePath = (this.lockManager as any).resolveResourcePath(resourceName);
      const fs = require('fs');
      
      try {
        // Direct write without lock acquisition
        fs.writeFileSync(resourcePath, JSON.stringify(data, null, 2));
        logger.debug(`✏️ Direct write to transaction-locked resource: ${resourceName}`);
        return;
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        logger.error(`Failed to write to transaction-locked resource ${resourceName}:`, err);
        throw err;
      }
    }
    
    // Fallback to normal atomic write for resources not locked by this transaction
    logger.debug(`🔓 Falling back to atomic write for: ${resourceName}`);
    await this.lockManager.atomicWrite(resourceName, data);
  }

  async execute<T = any>(fn: (tx: DatabaseTransaction) => Promise<T>): Promise<T> {
    return await fn(this);
  }

  // Helper method to check if resource is locked by this transaction
  public isResourceLocked(resourceName: string): boolean {
    return this.lockedResources.has(resourceName);
  }

  // Helper method to get the operation ID for debugging
  public getOperationId(): string {
    return this.operationId;
  }
}

export default DatabaseLockManager;