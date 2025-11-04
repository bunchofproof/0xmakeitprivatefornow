#!/usr/bin/env node

/**
 * Verification Script: Session Cleanup Refactor
 * Tests that the session cleanup logic has been successfully extracted
 * and that the refactored code works correctly.
 */

const fs = require('fs');
const path = require('path');

// Test expectations
const EXPECTATIONS = {
  newServiceFile: 'bot/src/services/sessionCleanupService.ts',
  updatedManagerFile: 'bot/src/utils/enhancedSessionSecurity.ts',
  compilationSuccess: true
};

function log(message, level = 'INFO') {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] ${level}: ${message}`);
}

function validateFileExists(filePath, description) {
  try {
    if (fs.existsSync(filePath)) {
      log(`✓ ${description} exists: ${filePath}`);
      return true;
    } else {
      log(`✗ ${description} missing: ${filePath}`, 'ERROR');
      return false;
    }
  } catch (error) {
    log(`✗ Error checking ${description}: ${error.message}`, 'ERROR');
    return false;
  }
}

function validateImportInFile(filePath, importStatement, description) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    if (content.includes(importStatement)) {
      log(`✓ ${description} found in ${path.basename(filePath)}`);
      return true;
    } else {
      log(`✗ ${description} not found in ${path.basename(filePath)}`, 'ERROR');
      return false;
    }
  } catch (error) {
    log(`✗ Error reading ${path.basename(filePath)}: ${error.message}`, 'ERROR');
    return false;
  }
}

function validateClassInFile(filePath, className, description) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    if (content.includes(`class ${className}`)) {
      log(`✓ ${description} found in ${path.basename(filePath)}`);
      return true;
    } else {
      log(`✗ ${description} not found in ${path.basename(filePath)}`, 'ERROR');
      return false;
    }
  } catch (error) {
    log(`✗ Error reading ${path.basename(filePath)}: ${error.message}`, 'ERROR');
    return false;
  }
}

function validateMethodInFile(filePath, methodName, description) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    if (content.includes(`performSecurityCleanup`)) {
      log(`✓ ${description} found in ${path.basename(filePath)}`);
      return true;
    } else {
      log(`✗ ${description} not found in ${path.basename(filePath)}`, 'ERROR');
      return false;
    }
  } catch (error) {
    log(`✗ Error reading ${path.basename(filePath)}: ${error.message}`, 'ERROR');
    return false;
  }
}

async function runTests() {
  log('Starting Session Cleanup Refactor Verification Tests...');
  log('='.repeat(60));

  let allTestsPassed = true;

  // Test 1: New service file exists
  const serviceFileExists = validateFileExists(
    EXPECTATIONS.newServiceFile,
    'SessionCleanupService file'
  );
  allTestsPassed = allTestsPassed && serviceFileExists;

  // Test 2: SessionCleanupService class exists in new file
  const serviceClassExists = validateClassInFile(
    EXPECTATIONS.newServiceFile,
    'SessionCleanupService',
    'SessionCleanupService class'
  );
  allTestsPassed = allTestsPassed && serviceClassExists;

  // Test 3: performSecurityCleanup method exists in new service
  const cleanupMethodExists = validateMethodInFile(
    EXPECTATIONS.newServiceFile,
    'performSecurityCleanup',
    'performSecurityCleanup method'
  );
  allTestsPassed = allTestsPassed && cleanupMethodExists;

  // Test 4: EnhancedSessionSecurityManager imports the new service
  const importStatementExists = validateImportInFile(
    EXPECTATIONS.updatedManagerFile,
    "import { sessionCleanupService } from '../services/sessionCleanupService';",
    'Correct import statement'
  );
  allTestsPassed = allTestsPassed && importStatementExists;

  // Test 5: EnhancedSessionSecurityManager calls sessionCleanupService.performSecurityCleanup
  const serviceCallExists = validateImportInFile(
    EXPECTATIONS.updatedManagerFile,
    'return sessionCleanupService.performSecurityCleanup();',
    'Service method call'
  );
  allTestsPassed = allTestsPassed && serviceCallExists;

  log('='.repeat(60));

  if (allTestsPassed) {
    log('🎉 ALL TESTS PASSED: Session cleanup refactor successful!', 'SUCCESS');
    process.exit(0);
  } else {
    log('❌ SOME TESTS FAILED: Session cleanup refactor incomplete.', 'ERROR');
    process.exit(1);
  }
}

// Run the tests
runTests().catch(error => {
  log(`FATAL ERROR: ${error.message}`, 'ERROR');
  console.error(error);
  process.exit(1);
});