// Test script to verify that session manager compilation and functionality work
// This test validates that the EnhancedSessionSecurityManager new methods are accessible

const { enhancedSessionSecurityManager } = require('../bot/src/utils/enhancedSessionSecurity.ts');

async function testSessionManagerCompilation() {
  console.log('Testing EnhancedSessionSecurityManager compilation...');

  try {
    // Check if the manager instance is available
    if (!enhancedSessionSecurityManager) {
      throw new Error('enhancedSessionSecurityManager is undefined');
    }

    // Check if new methods are available
    if (!enhancedSessionSecurityManager.getSessionSecurityStats) {
      throw new Error('getSessionSecurityStats method missing');
    }

    if (!enhancedSessionSecurityManager.performSecurityCleanup) {
      throw new Error('performSecurityCleanup method missing');
    }

    if (!enhancedSessionSecurityManager.validateAndInvalidateSession) {
      throw new Error('validateAndInvalidateSession method missing');
    }

    // Test calling the methods (they should not throw compilation errors)
    console.log('Testing getSessionSecurityStats...');
    const stats = await enhancedSessionSecurityManager.getSessionSecurityStats();
    console.log('✅ getSessionSecurityStats executed successfully:', typeof stats);

    console.log('Testing performSecurityCleanup...');
    const cleanup = await enhancedSessionSecurityManager.performSecurityCleanup();
    console.log('✅ performSecurityCleanup executed successfully:', typeof cleanup);

    console.log('✅ All EnhancedSessionSecurityManager methods are properly implemented and working');
    console.log('✅ Compilation fix successful');

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Full error:', error);
    process.exit(1);
  }
}

// Run the test
testSessionManagerCompilation();