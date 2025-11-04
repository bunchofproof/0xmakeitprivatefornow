const { PrismaClient } = require('../backend/node_modules/@prisma/client');

const prisma = new PrismaClient();

// Test to verify that VerificationHistory can be created without discordUserId (optional FK)
async function testVerificationHistoryOptionalFK() {
  console.log('Testing VerificationHistory with optional discordUserId FK...');

  try {
    // Test 1: Create VerificationHistory without discordUserId first (the main fix)
      console.log('Test 1: Creating VerificationHistory without discordUserId (null)...');
      const history1 = await prisma.verificationHistory.create({
        data: {
          discordUserId: null, // Optional FK - this was the fix
          success: true,
          timestamp: new Date(),
          errorMessage: null,
          createdAt: new Date(),
        },
      });
      console.log('✓ Success: VerificationHistory created without discordUserId - ID:', history1.id);

    // Test 2: Create VerificationHistory with discordUserId (should work if AdminVerification exists)
      console.log('Test 2: Creating VerificationHistory with discordUserId...');
      const adminUser = await prisma.adminVerification.create({
        data: {
          discordUserId: '123456789012345678',
          passportFingerprint: 'fingerprint123',
          uniqueIdentifier: 'unique123',
          lastVerified: new Date(),
          isActive: true,
        },
      });
      console.log('✓ Created AdminVerification for testing with discordUserId');
  
      const history2 = await prisma.verificationHistory.create({
        data: {
          discordUserId: '123456789012345678', // Valid Discord user ID that exists
          success: false,
          timestamp: new Date(),
          errorMessage: 'Test error message',
          createdAt: new Date(),
        },
      });
      console.log('✓ Success: VerificationHistory created with discordUserId - ID:', history2.id);

    // Test 3: Verify the records exist in database
    console.log('Test 3: Verifying records in database...');
    const count = await prisma.verificationHistory.count();
    console.log(`✓ Found ${count} VerificationHistory records in database`);

    const records = await prisma.verificationHistory.findMany({
      where: {
        id: { in: [history1.id, history2.id] },
      },
      select: {
        id: true,
        discordUserId: true,
        success: true,
        errorMessage: true,
      },
    });

    console.log('✓ Records retrieved:');
    records.forEach(record => {
      console.log(`  ID: ${record.id}, discordUserId: ${record.discordUserId}, success: ${record.success}, errorMessage: ${record.errorMessage}`);
    });

    // Test 4: Clean up test data
    console.log('Test 4: Cleaning up test data...');
    await prisma.verificationHistory.deleteMany({
      where: {
        id: { in: [history1.id, history2.id] },
      },
    });
    await prisma.adminVerification.deleteMany({
      where: {
        discordUserId: '123456789012345678',
      },
    });
    console.log('✓ Test data cleaned up');

    console.log('\n🎉 All tests passed! VerificationHistory discordUserId is now optional.');
    return true;

  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Stack:', error.stack);
    return false;
  } finally {
    await prisma.$disconnect();
  }
}

// Run the test
testVerificationHistoryOptionalFK().then(success => {
  process.exit(success ? 0 : 1);
});