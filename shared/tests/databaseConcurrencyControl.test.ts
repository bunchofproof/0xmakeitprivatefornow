/**
 * Comprehensive Database Concurrency Control and Race Condition Prevention Tests
 * Tests the shared DatabaseLockManager implementation for robustness under concurrent load
 */

import { DatabaseLockManager, LockType } from '../src/utils/databaseLockManager';
import * as fs from 'fs';
import * as path from 'path';
import { tmpdir } from 'os';

describe('DatabaseLockManager - Concurrency Control Tests', () => {
  let testDir: string;
  let lockManager: DatabaseLockManager;

  beforeEach(() => {
    // Create isolated test directory
    testDir = path.join(tmpdir(), `db-lock-test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`);
    fs.mkdirSync(testDir, { recursive: true });
    lockManager = new DatabaseLockManager(testDir);
  });

  afterEach(async () => {
    // Cleanup test directory
    try {
      await lockManager.forceReleaseAll();
      if (fs.existsSync(testDir)) {
        fs.rmSync(testDir, { recursive: true, force: true });
      }
    } catch (error) {
      console.warn('Cleanup failed:', error);
    }
  });

  describe('Basic Lock Operations', () => {
    test('should acquire and release exclusive lock', async () => {
      const lock = await lockManager.acquireLock('test.txt', LockType.EXCLUSIVE, 1000);
      expect(lockManager.isLocked('test.txt')).toBe(true);
      await lock.release();
      expect(lockManager.isLocked('test.txt')).toBe(false);
    });

    test('should acquire and release shared lock', async () => {
      const lock = await lockManager.acquireLock('test.txt', LockType.SHARED, 1000);
      expect(lockManager.isLocked('test.txt')).toBe(true);
      await lock.release();
      expect(lockManager.isLocked('test.txt')).toBe(false);
    });

    test('should prevent exclusive lock when shared lock is active', async () => {
      const sharedLock = await lockManager.acquireLock('test.txt', LockType.SHARED, 1000);
      
      // Try to acquire exclusive lock - should timeout
      await expect(
        lockManager.acquireLock('test.txt', LockType.EXCLUSIVE, 100)
      ).rejects.toThrow('Failed to acquire lock within timeout');
      
      await sharedLock.release();
      expect(lockManager.isLocked('test.txt')).toBe(false);
    });

    test('should prevent shared lock when exclusive lock is active', async () => {
      const exclusiveLock = await lockManager.acquireLock('test.txt', LockType.EXCLUSIVE, 1000);
      
      // Try to acquire shared lock - should timeout
      await expect(
        lockManager.acquireLock('test.txt', LockType.SHARED, 100)
      ).rejects.toThrow('Failed to acquire lock within timeout');
      
      await exclusiveLock.release();
      expect(lockManager.isLocked('test.txt')).toBe(false);
    });
  });

  describe('Atomic File Operations', () => {
    test('should perform atomic write', async () => {
      const testData = { test: 'data', timestamp: Date.now() };
      
      await lockManager.atomicWrite('test.json', testData);
      
      const filePath = path.join(testDir, 'test.json');
      expect(fs.existsSync(filePath)).toBe(true);
      
      const content = fs.readFileSync(filePath, 'utf8');
      expect(JSON.parse(content)).toEqual(testData);
    });

    test('should perform atomic read', async () => {
      const testData = { test: 'data', timestamp: Date.now() };
      
      // Write test data
      await lockManager.atomicWrite('test.json', testData);
      
      // Read test data
      const readData = await lockManager.atomicRead('test.json');
      expect(readData).toEqual(testData);
    });

    test('should handle non-existent file read', async () => {
      const readData = await lockManager.atomicRead('nonexistent.json');
      expect(readData).toEqual([]);
    });
  });

  describe('Transaction Management', () => {
    test('should execute simple transaction', async () => {
      const resources = ['test1.json', 'test2.json'];
      const testData = { test: 'transaction', timestamp: Date.now() };
      
      await lockManager.executeTransaction(resources, async (tx) => {
        await tx.write('test1.json', testData);
        const data = await tx.read('test2.json');
        data.push({ source: 'transaction' });
        await tx.write('test2.json', data);
      });
      
      // Verify both files were written
      const file1Path = path.join(testDir, 'test1.json');
      const file2Path = path.join(testDir, 'test2.json');
      
      expect(fs.existsSync(file1Path)).toBe(true);
      expect(fs.existsSync(file2Path)).toBe(true);
      
      expect(JSON.parse(fs.readFileSync(file1Path, 'utf8'))).toEqual(testData);
      expect(JSON.parse(fs.readFileSync(file2Path, 'utf8'))).toEqual([{ source: 'transaction' }]);
    });

    test('should rollback transaction on error', async () => {
      const resources = ['test1.json', 'test2.json'];
      const initialData = { initial: 'data' };
      
      // Write initial data
      await lockManager.atomicWrite('test1.json', initialData);
      
      try {
        await lockManager.executeTransaction(resources, async (tx) => {
          await tx.write('test1.json', { should: 'fail' });
          throw new Error('Simulated transaction failure');
        });
      } catch (error) {
        // Transaction should rollback
        const data = await lockManager.atomicRead('test1.json');
        expect(data).toEqual(initialData);
      }
    });
  });

  describe('Performance and Monitoring', () => {
    test('should handle multiple concurrent locks efficiently', async () => {
      const startTime = Date.now();
      const locks = [];
      
      // Acquire multiple shared locks concurrently
      for (let i = 0; i < 10; i++) {
        const lockPromise = lockManager.acquireLock(`file${i}.txt`, LockType.SHARED, 1000);
        locks.push(lockPromise);
      }
      
      const acquiredLocks = await Promise.all(locks);
      const duration = Date.now() - startTime;
      
      // Should complete within reasonable time (less than 1 second for local operations)
      expect(duration).toBeLessThan(1000);
      
      // Release all locks
      await Promise.all(acquiredLocks.map(lock => lock.release()));
    });

    test('should provide performance metrics', async () => {
      // Perform some operations to generate metrics
      await lockManager.atomicWrite('test.json', { test: 'data' });
      await lockManager.atomicRead('test.json');
      
      const metrics = await lockManager.getPerformanceMetrics();
      
      expect(metrics).toHaveProperty('totalOperations');
      expect(metrics).toHaveProperty('averageLockWaitTime');
      expect(metrics).toHaveProperty('deadlocksDetected');
      expect(metrics).toHaveProperty('activeLocks');
      expect(metrics.totalOperations).toBeGreaterThan(0);
    });
  });

  describe('Concurrency Stress Testing', () => {
    test('should handle 50 concurrent operations without deadlock', async () => {
      const operations = Array.from({ length: 50 }, (_, i) => 
        lockManager.executeTransaction([`file${i}.json`], async (tx) => {
          const data = await tx.read(`file${i}.json`);
          data.push({ operation: i, timestamp: Date.now() });
          await tx.write(`file${i}.json`, data);
        })
      );
      
      // All operations should complete successfully
      await expect(Promise.all(operations)).resolves.not.toThrow();
      
      // Verify no locks are stuck
      const activeLocks = await lockManager.getActiveLocks();
      expect(activeLocks.length).toBe(0);
    });

    test('should prevent deadlocks in complex transaction chains', async () => {
      // Simulate potential deadlock scenario
      const tx1 = lockManager.executeTransaction(['file1.json', 'file2.json'], async (tx) => {
        await tx.read('file1.json');
        await new Promise(resolve => setTimeout(resolve, 10)); // Small delay
        await tx.write('file2.json', { tx: 1 });
      });
      
      const tx2 = lockManager.executeTransaction(['file2.json', 'file1.json'], async (tx) => {
        await tx.read('file2.json');
        await new Promise(resolve => setTimeout(resolve, 10)); // Small delay
        await tx.write('file1.json', { tx: 2 });
      });
      
      // Both transactions should complete without deadlock
      await expect(Promise.all([tx1, tx2])).resolves.not.toThrow();
    });
  });

  describe('Session-Specific Locking', () => {
    test('should acquire and release session lock', async () => {
      const sessionId = 'test-session-123';
      const lock = await lockManager.acquireSessionLock(sessionId);
      
      expect(lockManager.isSessionLocked(sessionId)).toBe(true);
      await lock.release();
      expect(lockManager.isSessionLocked(sessionId)).toBe(false);
    });

    test('should prevent concurrent session operations', async () => {
      const sessionId = 'test-session-123';
      const lock1 = await lockManager.acquireSessionLock(sessionId);
      
      // Try to acquire another lock for same session - should timeout
      await expect(
        lockManager.acquireSessionLock(sessionId, 100)
      ).rejects.toThrow('Failed to acquire session lock within timeout');
      
      await lock1.release();
    });
  });
});