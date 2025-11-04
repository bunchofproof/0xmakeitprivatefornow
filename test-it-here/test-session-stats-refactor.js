const { getSessionSecurityStats } = require('../bot/dist/utils/sessionStatsService.js');
const { databaseDriver } = require('../bot/src/utils/databaseDrivers');

async function testSessionStatsRefactor() {
  console.log('Testing session stats refactor...');

  try {
    // Validate environment
    if (!process.env.DATABASE_URL) {
      throw new Error('DATABASE_URL environment variable is required');
    }

    // Get stats before creating test data
    const initialStats = await getSessionSecurityStats();
    console.log('Initial stats:', initialStats);

    // Create a test session
    const testSession = {
      id: 'test-session-' + Date.now(),
      token: 'test-token-' + Date.now(),
      discordUserId: 'test-user-123',
      expiresAt: new Date(Date.now() + 30 * 60 * 1000).toISOString(), // 30 minutes from now
      bindingHash: 'test-binding-hash',
      fingerprint: 'test-fingerprint',
      nonce: 'test-nonce',
      createdAt: new Date().toISOString(),
      usageCount: 0,
      sequenceNumber: 0
    };

    // Write test session to database
    await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx) => {
      const sessions = await tx.read('verification-sessions.json');
      sessions.push(testSession);
      await tx.write('verification-sessions.json', sessions);
    });

    console.log('Test session created:', testSession.id);

    // Get stats after creating test data
    const statsAfterCreation = await getSessionSecurityStats();
    console.log('Stats after creation:', statsAfterCreation);

    // Validate that stats reflect the new session
    if (statsAfterCreation.totalSessions !== initialStats.totalSessions + 1) {
      throw new Error(`Expected totalSessions to be ${initialStats.totalSessions + 1}, got ${statsAfterCreation.totalSessions}`);
    }

    if (statsAfterCreation.activeSessions !== initialStats.activeSessions + 1) {
      throw new Error(`Expected activeSessions to be ${initialStats.activeSessions + 1}, got ${statsAfterCreation.activeSessions}`);
    }

    console.log('✅ Session stats refactor test passed!');

    // Clean up test data
    await databaseDriver.executeTransaction(['verification-sessions.json'], async (tx) => {
      const sessions = await tx.read('verification-sessions.json');
      const filteredSessions = sessions.filter(s => s.id !== testSession.id);
      await tx.write('verification-sessions.json', filteredSessions);
    });

    console.log('Test data cleaned up');

  } catch (error) {
    console.error('❌ Session stats refactor test failed:', error.message);
    process.exit(1);
  }
}

// Run the test
testSessionStatsRefactor();