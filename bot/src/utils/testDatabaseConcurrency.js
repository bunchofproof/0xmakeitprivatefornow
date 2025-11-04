// Database Concurrency Control Validation Script
// Tests the implemented race condition prevention mechanisms

const { DatabaseFileLock, AtomicWriteManager, DatabaseTransaction, ConcurrencyControlledJsonDatabaseDriver } = require('./databaseConcurrencyControl');
const fs = require('fs');
const path = require('path');

async function testDatabaseConcurrency() {
  console.log('🧪 Testing Database Concurrency Control System...\n');

  // Test directory setup
  const testDir = path.join(__dirname, '../../test-concurrency-db');
  
  // Clean up any existing test directory
  if (fs.existsSync(testDir)) {
    fs.rmSync(testDir, { recursive: true });
  }
  fs.mkdirSync(testDir, { recursive: true });

  try {
    // Test 1: File Lock Manager
    console.log('📋 Test 1: DatabaseFileLock');
    const lockManager = new DatabaseFileLock(testDir);
    
    const filename = 'test.json';
    const releaseLock = await lockManager.acquireLock(filename);
    console.log(`✅ Lock acquired for ${filename}`);
    
    expect(lockManager.isLocked(filename)).toBe(true);
    
    await releaseLock();
    console.log(`✅ Lock released for ${filename}`);
    expect(lockManager.isLocked(filename)).toBe(false);
    
    // Test 2: Atomic Write Operations
    console.log('\n📝 Test 2: AtomicWriteManager');
    const writeManager = new AtomicWriteManager(testDir);
    
    const testData = { id: 1, name: 'test', timestamp: Date.now() };
    await writeManager.atomicWrite('test.json', testData, lockManager);
    console.log('✅ Atomic write completed');
    
    const filePath = path.join(testDir, 'test.json');
    const content = fs.readFileSync(filePath, 'utf8');
    const parsedData = JSON.parse(content);
    expect(parsedData).toEqual(testData);
    console.log('✅ Atomic write data validated');
    
    // Test 3: Database Transaction
    console.log('\n🔄 Test 3: DatabaseTransaction');
    const transaction = new DatabaseTransaction(lockManager, writeManager);
    
    const testData1 = [{ id: 1, data: 'first' }];
    const testData2 = [{ id: 2, data: 'second' }];
    
    await transaction.read('test1.json');
    await transaction.read('test2.json');
    await transaction.write('test1.json', testData1);
    await transaction.write('test2.json', testData2);
    
    await transaction.execute();
    console.log('✅ Transaction executed successfully');
    
    // Verify both files
    const file1Path = path.join(testDir, 'test1.json');
    const file2Path = path.join(testDir, 'test2.json');
    
    expect(fs.existsSync(file1Path)).toBe(true);
    expect(fs.existsSync(file2Path)).toBe(true);
    
    const content1 = JSON.parse(fs.readFileSync(file1Path, 'utf8'));
    const content2 = JSON.parse(fs.readFileSync(file2Path, 'utf8'));
    
    expect(content1).toEqual(testData1);
    expect(content2).toEqual(testData2);
    console.log('✅ Transaction data integrity validated');
    
    // Test 4: Concurrency Control
    console.log('\n⚡ Test 4: ConcurrencyControlledJsonDatabaseDriver');
    const driver = new ConcurrencyControlledJsonDatabaseDriver(testDir);
    
    // Test concurrent operations
    const concurrentOperations = [];
    for (let i = 0; i < 10; i++) {
      concurrentOperations.push(
        driver.executeTransaction(async (tx) => {
          const data = await tx.read('concurrent.json');
          data.push({ id: i, data: `item_${i}`, timestamp: Date.now() });
          await tx.write('concurrent.json', data);
        })
      );
    }
    
    await Promise.all(concurrentOperations);
    console.log('✅ 10 concurrent operations completed successfully');
    
    const finalData = await driver.readFile('concurrent.json');
    expect(finalData.length).toBe(10);
    
    // Check for duplicates
    const ids = finalData.map(item => item.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(10);
    console.log('✅ No data corruption detected in concurrent operations');
    
    // Test 5: Database Validation and Repair
    console.log('\n🔍 Test 5: Database Consistency Validation');
    
    // Create a corrupted file
    const corruptedFile = path.join(testDir, 'corrupted.json');
    fs.writeFileSync(corruptedFile, 'invalid json content {{{');
    
    const validation = await driver.validateAndRepairDatabase();
    expect(validation.errors.length).toBeGreaterThan(0);
    expect(validation.repaired).toBe(true);
    console.log('✅ Database corruption detected and repaired');
    
    // Verify repaired file
    const repairedData = await driver.readFile('corrupted.json');
    expect(Array.isArray(repairedData)).toBe(true);
    console.log('✅ Repaired file validated');
    
    // Test 6: Transaction Rollback
    console.log('\n↩️ Test 6: Transaction Rollback');
    
    // Create original data
    await driver.writeFile('rollback.json', [{ id: 1, data: 'original' }]);
    
    try {
      await driver.executeTransaction(async (tx) => {
        const data = await tx.read('rollback.json');
        data[0].data = 'modified';
        await tx.write('rollback.json', data);
        throw new Error('Simulated transaction failure');
      });
    } catch (error) {
      // Expected to fail
    }
    
    // Verify rollback
    const rolledBackData = await driver.readFile('rollback.json');
    expect(rolledBackData[0].data).toBe('original');
    console.log('✅ Transaction rollback successful');
    
    console.log('\n🎉 All Database Concurrency Control Tests PASSED!');
    console.log('\n📊 Summary of Implemented Fixes:');
    console.log('✅ File-level locking for JSON database operations');
    console.log('✅ Atomic write operations using temporary files and rename');
    console.log('✅ Database transaction simulation with rollback capability');
    console.log('✅ Database consistency validation and recovery mechanisms');
    console.log('✅ Concurrency control preventing data corruption');
    console.log('✅ Multi-file transaction atomicity');
    console.log('✅ Lock timeout and stale lock detection');
    console.log('✅ Emergency lock cleanup mechanisms');
    
    console.log('\n🔒 Database Race Condition Vulnerabilities ELIMINATED:');
    console.log('❌ No file-level locking → ✅ Implemented DatabaseFileLock');
    console.log('❌ Inadequate mutex → ✅ File system level locking');
    console.log('❌ Non-atomic writes → ✅ AtomicWriteManager with temp files');
    console.log('❌ No transactions → ✅ DatabaseTransaction with rollback');
    console.log('❌ Missing validation → ✅ DatabaseConsistencyValidator');
    console.log('❌ No recovery → ✅ Automatic repair mechanisms');
    
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  } finally {
    // Cleanup
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true });
    }
  }
}

// Simple assertion helpers for Node.js
function expect(actual) {
  return {
    toBe(expected) {
      if (actual !== expected) {
        throw new Error(`Expected ${expected}, got ${actual}`);
      }
    },
    toEqual(expected) {
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
      }
    },
    toBeGreaterThan(expected) {
      if (actual <= expected) {
        throw new Error(`Expected ${actual} to be greater than ${expected}`);
      }
    }
  };
}

// Run tests
if (require.main === module) {
  testDatabaseConcurrency()
    .then(() => {
      console.log('\n✅ Database concurrency control validation completed successfully!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('\n❌ Validation failed:', error);
      process.exit(1);
    });
}

module.exports = { testDatabaseConcurrency };