#!/usr/bin/env node

/**
 * Test Current Session Creation
 * This test verifies that session creation includes the critical ID field
 */

const { databaseDriver } = require('./bot/src/utils/databaseDrivers');

// Test data
const testSessionData = {
  id: 'test-session-id-12345678901234567890',
  token: 'test-token-1234567890123456789012345678901234567890',
  discordUserId: '123456789012345678',
  expiresAt: new Date(Date.now() + 30 * 60 * 1000),
};

async function testSessionCreation() {
  console.log('🧪 Testing current session creation functionality...\n');

  try {
    console.log('📝 Test Session Data:');
    console.log(JSON.stringify(testSessionData, null, 2));
    console.log();

    console.log('🔄 Creating verification session...');
    const session = await databaseDriver.instance.createVerificationSession(testSessionData);
    
    console.log('✅ Session created successfully!');
    console.log('📋 Session Response:');
    console.log(JSON.stringify(session, null, 2));
    console.log();

    // Verify critical fields
    console.log('🔍 Verification:');
    console.log(`✅ ID field present: ${session.id ? 'YES' : 'NO'}`);
    console.log(`✅ Token field present: ${session.token ? 'YES' : 'NO'}`);
    console.log(`✅ Discord User ID: ${session.discordUserId}`);
    console.log(`✅ Status: ${session.status}`);
    console.log(`✅ Attempts: ${session.attempts}/${session.maxAttempts}`);
    console.log();

    if (!session.id) {
      console.error('❌ CRITICAL: ID field is missing from session!');
      process.exit(1);
    }

    console.log('✅ All critical fields present - Session creation working correctly!');
    
  } catch (error) {
    console.error('❌ Session creation failed:');
    console.error('Error Type:', error.constructor.name);
    console.error('Error Message:', error.message);
    console.error('Error Stack:', error.stack);
    process.exit(1);
  }
}

// Run the test
testSessionCreation().then(() => {
  console.log('\n🎉 Test completed successfully!');
}).catch((error) => {
  console.error('\n💥 Test failed:', error);
  process.exit(1);
});