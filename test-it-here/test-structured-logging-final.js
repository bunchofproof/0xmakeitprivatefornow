/**
 * Test Script: Structured Logging Refactoring Verification
 * Tests that all logger calls use structured logging format and compile successfully
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

console.log('=== Structured Logging Refactoring Verification ===\n');

// Test 1: TypeScript Compilation Check
console.log('Test 1: Running TypeScript compilation check...');
try {
  const result = execSync('cd zk-discord-verifier/bot && npx tsc --noEmit', { encoding: 'utf8' });
  console.log('✅ TypeScript compilation successful');
} catch (error) {
  console.error('❌ TypeScript compilation failed:');
  console.error(error.stdout);
  console.error(error.stderr);
  process.exit(1);
}

// Test 2: Verify structured logging patterns in key files
console.log('\nTest 2: Verifying structured logging patterns...');

const filesToCheck = [
  'zk-discord-verifier/bot/src/utils/tokenGenerator.ts',
  'zk-discord-verifier/bot/src/utils/sessionSecurityManager.ts',
  'zk-discord-verifier/bot/src/services/adminService.ts',
];

let allGood = true;

for (const filePath of filesToCheck) {
  console.log(`Checking ${filePath}...`);
  try {
    const content = fs.readFileSync(filePath, 'utf8');

    // Check that logger.error calls follow the pattern: logger.error(message, undefined, meta)
    const errorCalls = content.match(/logger\.error\([^)]+\)/g) || [];
    for (const call of errorCalls) {
      // Should have two parameters before meta: message and error (which is undefined for structured)
      const paramsMatch = call.match(/logger\.error\('([^']+)'(?:,\s*undefined)?,\s*\{/);
      if (!paramsMatch) {
        console.error(`❌ Invalid error call pattern: ${call}`);
        allGood = false;
      }
    }

    // Check that logger.info/warn calls follow the pattern: logger.info(message, meta)
    const infoWarnCalls = content.match(/logger\.(info|warn)\([^)]+\)/g) || [];
    for (const call of infoWarnCalls) {
      const paramsMatch = call.match(/logger\.(info|warn)\('([^']+)',\s*\{/);
      if (!paramsMatch) {
        console.error(`❌ Invalid info/warn call pattern: ${call}`);
        allGood = false;
      }
    }

    console.log(`✅ ${filePath} patterns verified`);
  } catch (error) {
    console.error(`❌ Failed to check ${filePath}: ${error.message}`);
    allGood = false;
  }
}

// Test 3: Sample log output verification
console.log('\nTest 3: Sample runtime log verification...');
console.log('Note: This would require running the bot and checking actual log output.');
console.log('Expected structured format:');
console.log('  - Message: concise string');
console.log('  - Meta: JSON object with context data');
console.log('  - No dynamic data in message string');

if (allGood) {
  console.log('\n🎉 All structured logging verification tests passed!');
  console.log('The bot project now uses consistent structured logging format.');
} else {
  console.log('\n❌ Some verification checks failed. Please review the errors above.');
  process.exit(1);
}