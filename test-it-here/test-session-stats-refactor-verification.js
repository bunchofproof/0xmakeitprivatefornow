// Test that the session stats service can be imported and used
const { enhancedSessionSecurityManager } = require('../bot/dist/utils/enhancedSessionSecurity.js');

async function testSessionStatsRefactor() {
  console.log('[TEST] Starting session stats refactor verification...');

  try {
    // Test that the service is accessible and functional
    const stats = await enhancedSessionSecurityManager.getSessionSecurityStats();

    console.log('[TEST] Session stats retrieved successfully:', stats);

    // Verify the stats object has expected properties
    const expectedProperties = [
      'totalSessions',
      'activeSessions',
      'expiredSessions',
      'compromisedSessions',
      'replayAttempts',
      'bindingViolations',
      'securityEvents',
      'timestamp',
      'systemHealthy'
    ];

    const missingProperties = expectedProperties.filter(prop => !(prop in stats));
    if (missingProperties.length > 0) {
      throw new Error(`Missing properties in stats object: ${missingProperties.join(', ')}`);
    }

    console.log('[TEST] ✅ All expected properties present in stats object');

    // Verify that stats are reasonable (numbers, boolean for healthy)
    if (typeof stats.totalSessions !== 'number' || stats.totalSessions < 0) {
      throw new Error('totalSessions must be a non-negative number');
    }
    if (typeof stats.activeSessions !== 'number' || stats.activeSessions < 0) {
      throw new Error('activeSessions must be a non-negative number');
    }
    if (typeof stats.expiredSessions !== 'number' || stats.expiredSessions < 0) {
      throw new Error('expiredSessions must be a non-negative number');
    }
    if (typeof stats.compromisedSessions !== 'number' || stats.compromisedSessions < 0) {
      throw new Error('compromisedSessions must be a non-negative number');
    }
    if (typeof stats.replayAttempts !== 'number' || stats.replayAttempts < 0) {
      throw new Error('replayAttempts must be a non-negative number');
    }
    if (typeof stats.bindingViolations !== 'number' || stats.bindingViolations < 0) {
      throw new Error('bindingViolations must be a non-negative number');
    }
    if (typeof stats.securityEvents !== 'number' || stats.securityEvents < 0) {
      throw new Error('securityEvents must be a non-negative number');
    }
    if (!(stats.timestamp instanceof Date)) {
      throw new Error('timestamp must be a Date object');
    }
    if (typeof stats.systemHealthy !== 'boolean') {
      throw new Error('systemHealthy must be a boolean');
    }

    console.log('[TEST] ✅ All stats properties have correct types and reasonable values');

    // Verify that the system healthy calculation is correct
    const expectedHealthy = stats.replayAttempts < 10 && stats.bindingViolations < 5;
    if (stats.systemHealthy !== expectedHealthy) {
      throw new Error(`systemHealthy calculation is incorrect. Expected: ${expectedHealthy}, Got: ${stats.systemHealthy}`);
    }

    console.log('[TEST] ✅ System healthy calculation is correct');

    console.log('[TEST] 🎉 Session stats refactor verification PASSED');

  } catch (error) {
    console.error('[TEST] ❌ Session stats refactor verification FAILED:', error.message);
    process.exit(1);
  }
}

// Run the test
testSessionStatsRefactor().catch(error => {
  console.error('[TEST] Unexpected error during verification:', error);
  process.exit(1);
});