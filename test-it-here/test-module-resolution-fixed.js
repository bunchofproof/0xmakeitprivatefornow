#!/usr/bin/env node

/**
 * Verification Script: Module Resolution Fixed
 * Tests that the bot can successfully import shared utilities without module resolution errors
 */

const { spawn } = require('child_process');

async function testModuleResolution() {
  console.log('🧪 Testing Module Resolution Fix...');

  try {
    // Change to bot directory
    process.chdir('../bot');

    console.log('📂 Changed to bot directory');

    // Test TypeScript compilation to verify imports resolve correctly
    console.log('🔍 Running TypeScript compilation check...');

    const tsc = spawn('npx', ['tsc', '--noEmit'], {
      stdio: 'inherit',
      cwd: process.cwd()
    });

    return new Promise((resolve, reject) => {
      tsc.on('close', (code) => {
        if (code === 0) {
          console.log('✅ TypeScript compilation successful - imports resolved correctly');
          resolve(true);
        } else {
          console.log('❌ TypeScript compilation failed - module resolution error persists');
          reject(new Error(`TypeScript compilation failed with code ${code}`));
        }
      });

      tsc.on('error', (error) => {
        console.log('❌ Failed to run TypeScript compiler:', error.message);
        reject(error);
      });
    });

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    throw error;
  }
}

// Run the test
testModuleResolution()
  .then(() => {
    console.log('🎉 Module resolution fix verified successfully!');
    process.exit(0);
  })
  .catch((error) => {
    console.error('💥 Module resolution fix verification failed:', error.message);
    process.exit(1);
  });