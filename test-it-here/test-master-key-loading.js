#!/usr/bin/env node

/**
 * Master Key Loading Test Script
 *
 * Tests the secure key manager's ability to load the master encryption key
 * from the MASTER_ENCRYPTION_KEY environment variable.
 */

const path = require('path');
const fs = require('fs');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '../backend/.env.development') });

// Import the secure key manager
const { secureKeyManager } = require('../backend/src/services/secureKeyManager.ts');

async function testMasterKeyLoading() {
  console.log('🧪 Testing Master Key Loading...\n');

  try {
    // Test 1: Check if MASTER_ENCRYPTION_KEY is set
    const masterKey = process.env.MASTER_ENCRYPTION_KEY;
    if (!masterKey) {
      throw new Error('MASTER_ENCRYPTION_KEY environment variable is not set');
    }
    console.log('✅ MASTER_ENCRYPTION_KEY is set');

    // Test 2: Check minimum length
    if (masterKey.length < 16) {
      throw new Error('MASTER_ENCRYPTION_KEY is too short (minimum 16 characters)');
    }
    console.log('✅ MASTER_ENCRYPTION_KEY meets minimum length requirement');

    // Test 3: Attempt to create a key (this will trigger encryptKeyMaterial)
    console.log('🔄 Testing key creation that uses master encryption key...');
    const testKeyId = await secureKeyManager.createKey({
      name: 'test-master-key-validation',
      algorithm: 'aes-256-gcm',
      keyType: 'aes',
      purpose: 'testing',
      keyUsage: ['encrypt', 'decrypt'],
      allowedOperations: ['encrypt', 'decrypt'],
      environment: 'development'
    });

    if (!testKeyId) {
      throw new Error('Failed to create test key');
    }
    console.log(`✅ Test key created successfully: ${testKeyId}`);

    // Test 4: Attempt to get the key
    const keyData = await secureKeyManager.getKey(testKeyId);
    if (!keyData) {
      throw new Error('Failed to retrieve created test key');
    }
    console.log('✅ Test key retrieved successfully');

    // Test 5: Verify the key manager initializes without errors
    await secureKeyManager.initializeKeyManager();
    console.log('✅ Key manager initialized successfully');

    console.log('\n🎉 All master key loading tests passed!');
    return true;

  } catch (error) {
    console.error('\n❌ Master key loading test failed:', error.message);
    return false;
  }
}

async function testMissingMasterKey() {
  console.log('\n🧪 Testing missing MASTER_ENCRYPTION_KEY...\n');

  // Temporarily unset the environment variable
  const originalKey = process.env.MASTER_ENCRYPTION_KEY;
  delete process.env.MASTER_ENCRYPTION_KEY;

  try {
    // This should fail when trying to create a key
    const testKeyId = await secureKeyManager.createKey({
      name: 'test-missing-key',
      algorithm: 'aes-256-gcm',
      keyType: 'aes',
      purpose: 'testing',
      keyUsage: ['encrypt', 'decrypt'],
      allowedOperations: ['encrypt', 'decrypt'],
      environment: 'development'
    });

    console.error('❌ Expected error when MASTER_ENCRYPTION_KEY is missing, but key creation succeeded');
    return false;

  } catch (error) {
    if (error.message.includes('MASTER_ENCRYPTION_KEY environment variable is required')) {
      console.log('✅ Correctly threw error when MASTER_ENCRYPTION_KEY is missing');
      return true;
    } else {
      console.error('❌ Unexpected error:', error.message);
      return false;
    }
  } finally {
    // Restore the original key
    if (originalKey) {
      process.env.MASTER_ENCRYPTION_KEY = originalKey;
    }
  }
}

async function runTests() {
  console.log('🚀 Starting Master Key Loading Verification Tests\n');

  const test1Result = await testMasterKeyLoading();
  const test2Result = await testMissingMasterKey();

  console.log('\n📊 Test Results:');
  console.log(`Master key loading: ${test1Result ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Missing key error: ${test2Result ? '✅ PASS' : '❌ FAIL'}`);

  if (test1Result && test2Result) {
    console.log('\n🎯 All verification tests passed! Master encryption key remediation is successful.');
    process.exit(0);
  } else {
    console.log('\n💥 Some tests failed. Please check the implementation.');
    process.exit(1);
  }
}

// Run the tests
runTests().catch(error => {
  console.error('Test execution failed:', error);
  process.exit(1);
});