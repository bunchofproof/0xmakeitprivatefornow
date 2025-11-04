const { PrismaClient } = require('@prisma/client');
const crypto = require('crypto');

// Test script to verify that verification sessions can be created for unverified users
async function testSessionCreationForUnverifiedUser() {
  const prisma = new PrismaClient();

  try {
    console.log('Starting test: Session creation for unverified user');

    // Generate a mock Discord user ID (unverified user)
    const discordUserId = crypto.randomUUID();

    console.log(`Generated mock Discord user ID: ${discordUserId}`);

    // Check that no AdminVerification exists for this user
    const existingVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId }
    });

    if (existingVerification) {
      console.log('ERROR: AdminVerification already exists for this user - test invalid');
      return false;
    }

    console.log('Confirmed: No AdminVerification exists for this user');

    // Attempt to create a verification session
    const session = await prisma.verificationSession.create({
      data: {
        discordUserId,
        token: crypto.randomBytes(32).toString('hex'),
        expiresAt: new Date(Date.now() + 3600000), // 1 hour from now
        bindingHash: crypto.randomBytes(32).toString('hex'),
        lastContextHash: crypto.randomBytes(32).toString('hex')
      }
    });

    console.log(`SUCCESS: Verification session created with ID: ${session.id}`);
    console.log(`Session details:`, {
      id: session.id,
      discordUserId: session.discordUserId,
      token: session.token.substring(0, 10) + '...', // Truncate for security
      expiresAt: session.expiresAt,
      used: session.used,
      createdAt: session.createdAt
    });

    // Verify the session exists in the database
    const retrievedSession = await prisma.verificationSession.findUnique({
      where: { id: session.id }
    });

    if (!retrievedSession) {
      console.log('ERROR: Session was not persisted in database');
      return false;
    }

    console.log('SUCCESS: Session verified in database');

    // Cleanup: Delete the test session
    await prisma.verificationSession.delete({
      where: { id: session.id }
    });

    console.log('Cleanup: Test session deleted');

    console.log('TEST PASSED: Verification sessions can be created for unverified users');
    return true;

  } catch (error) {
    console.error('TEST FAILED: Error occurred during test execution', error);
    return false;
  } finally {
    await prisma.$disconnect();
  }
}

// Run the test
testSessionCreationForUnverifiedUser()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });