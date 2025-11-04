const { PrismaClient } = require('@prisma/client');
const { PrismaDatabaseDriver } = require('../bot/dist/bot/src/utils/drivers/prismaDriver');

console.log('Starting test: Session creation should not create admin verification placeholder');

// Initialize Prisma client
const prisma = new PrismaClient();

async function testSessionCreationNoAdminPlaceholder() {
  try {
    // Clean up any existing test data
    await prisma.verificationSession.deleteMany({
      where: {
        discordUserId: 'test-user-123',
      },
    });
    await prisma.adminVerification.deleteMany({
      where: {
        discordUserId: 'test-user-123',
      },
    });

    // Initialize the database driver
    const driver = new PrismaDatabaseDriver();
    await driver.initializeDatabase();

    // Check initial state: no admin verification exists
    const initialAdminVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId: 'test-user-123' },
    });
    if (initialAdminVerification !== null) {
      throw new Error('Initial state check failed: Admin verification already exists');
    }

    // Create a verification session
    const sessionData = {
      id: 'test-session-123',
      token: 'test-token-abc',
      discordUserId: 'test-user-123',
      expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
    };

    const createdSession = await driver.createVerificationSession(sessionData);

    // Verify session was created
    if (!createdSession || createdSession.id !== 'test-session-123') {
      throw new Error('Session creation failed: Session not created correctly');
    }

    // Verify session exists in database
    const dbSession = await prisma.verificationSession.findUnique({
      where: { id: 'test-session-123' },
    });
    if (!dbSession) {
      throw new Error('Database check failed: Session not found in database');
    }

    // Critical test: Verify NO admin verification was created
    const adminVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId: 'test-user-123' },
    });
    if (adminVerification !== null) {
      throw new Error('Test failed: Admin verification placeholder was created when it should not have been');
    }

    console.log('✅ Test passed: Session created without admin verification placeholder');

    // Clean up
    await prisma.verificationSession.deleteMany({
      where: {
        discordUserId: 'test-user-123',
      },
    });

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    process.exit(1);
  } finally {
    await prisma.$disconnect();
  }
}

// Run the test
testSessionCreationNoAdminPlaceholder().then(() => {
  console.log('Test completed');
}).catch((error) => {
  console.error('Test runner error:', error);
  process.exit(1);
});