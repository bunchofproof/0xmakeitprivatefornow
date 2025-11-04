#!/usr/bin/env node

/**
 * Verification script for bot structured logging implementation
 * Tests that TypeScript compilation succeeds and logging works correctly
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('🧪 Testing bot structured logging compilation and functionality...');

try {
  // Test 1: TypeScript compilation
  console.log('📝 Testing TypeScript compilation...');
  const output = execSync('cd bot && npx tsc --noEmit', {
    encoding: 'utf8',
    cwd: path.join(__dirname, '..')
  });

  if (output.trim() === '') {
    console.log('✅ TypeScript compilation successful - no errors found');
  } else {
    console.log('❌ TypeScript compilation failed with output:', output);
    process.exit(1);
  }

  // Test 2: Check for remaining problematic logger calls
  console.log('🔍 Checking for remaining logger call issues...');
  const remainingIssues = execSync('grep -r "logger\.(info|warn|error).*undefined.*Record<string, any>" bot/src/ || echo "No issues found"', {
    encoding: 'utf8',
    cwd: path.join(__dirname, '..')
  });

  if (remainingIssues.trim() === 'No issues found') {
    console.log('✅ No remaining logger call issues found');
  } else {
    console.log('❌ Found remaining logger call issues:', remainingIssues);
    process.exit(1);
  }

  // Test 3: Basic import test
  console.log('📦 Testing logger import and basic functionality...');
  const loggerModule = require('../shared/src/utils/logger.ts');

  if (loggerModule && loggerModule.logger) {
    console.log('✅ Logger module imports successfully');
  } else {
    console.log('❌ Logger module import failed');
    process.exit(1);
  }

  console.log('🎉 All bot structured logging tests passed!');

} catch (error) {
  console.error('❌ Test failed:', error.message);
  process.exit(1);
}