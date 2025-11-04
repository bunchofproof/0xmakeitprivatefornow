// Test script to verify the createdAt column fix in VerificationHistory model
// This script tests that verificationHistory.create operations no longer fail due to schema mismatch

const axios = require('axios');
const crypto = require('crypto');

// Configuration
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:3001';

// Use Prisma client directly
process.env.DATABASE_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Test data - generate valid session ID (64 hex chars)
const testUserId = 'test-user-' + crypto.randomBytes(8).toString('hex');
const testSessionId = crypto.randomBytes(32).toString('hex');

async function testVerificationHistoryCreate() {
  console.log('🧪 Testing VerificationHistory.create fix');

  try {
    // Step 1: Create a test user and session to simulate real verification flow
    console.log('Creating test user and session...');

    const user = await prisma.user.upsert({
      where: { userId: testUserId },
      update: {},
      create: {
        userId: testUserId,
        accessToken: crypto.randomBytes(32).toString('hex'),
        refreshToken: crypto.randomBytes(32).toString('hex')
      }
    });

    const session = await prisma.verificationSession.create({
      data: {
        id: testSessionId,
        token: crypto.randomBytes(32).toString('hex'),
        discordUserId: testUserId,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
        used: false,
        bindingHash: crypto.randomBytes(32).toString('hex'),
        lastContextHash: crypto.randomBytes(32).toString('hex')
      }
    });

    console.log('✅ Test data created successfully');

    // Step 2: Test successful verification (this should create VerificationHistory record)
    console.log('Testing successful verification flow...');

    // Mock proof data (using same approach as test-verification-state-management.js)
    const mockProofs = [{
      proof: 'mock-proof-data',
      publicSignals: ['signal1', 'signal2']
    }];

    const response = await axios.post(`${BACKEND_URL}/api/verify/proof`, {
      proofs: mockProofs,
      sessionId: testSessionId,
      token: session.token,
      domain: 'test-domain',
      verificationType: 'personhood'
    });

    console.log('API Response Status:', response.status);

    // Step 3: Verify that VerificationHistory record was created without createdAt column error
    if (response.status === 200 && response.data.verified === true) {
      console.log('✅ Verification successful - VerificationHistory.create should have worked');

      // Check that a VerificationHistory record exists
      const historyRecord = await prisma.verificationHistory.findFirst({
        where: { discordUserId: testUserId, success: true }
      });

      if (historyRecord) {
        console.log('✅ VerificationHistory record found with expected fields:');
        console.log('   - id:', historyRecord.id);
        console.log('   - discordUserId:', historyRecord.discordUserId);
        console.log('   - success:', historyRecord.success);
        console.log('   - timestamp:', historyRecord.timestamp);
        console.log('   - errorMessage:', historyRecord.errorMessage);

        // Check that createdAt field is NOT present (removed from schema)
        if (!historyRecord.createdAt) {
          console.log('✅ PASS: createdAt field correctly removed from schema');
          return true;
        } else {
          console.log('❌ FAIL: createdAt field still exists in schema');
          return false;
        }
      } else {
        console.log('❌ FAIL: No VerificationHistory record found');
        return false;
      }
    } else {
      console.log('❌ FAIL: Verification failed with status', response.status);
      console.log('Response:', response.data);
      return false;
    }

  } catch (error) {
    console.log('❌ ERROR during test:', error.response?.data || error.message);

    // Check if the error is the createdAt column error we were fixing
    if (error.message.includes("The column `createdAt` does not exist")) {
      console.log('❌ FAIL: createdAt column error still occurs - fix did not work');
      return false;
    } else {
      console.log('❌ FAIL: Unexpected error occurred');
      return false;
    }
  } finally {
    // Cleanup
    console.log('🧹 Cleaning up test data...');
    await prisma.verificationHistory.deleteMany({ where: { discordUserId: testUserId } });
    await prisma.adminVerification.deleteMany({ where: { discordUserId: testUserId } });
    await prisma.verificationSession.deleteMany({ where: { id: testSessionId } });
    await prisma.user.deleteMany({ where: { userId: testUserId } });
    await prisma.$disconnect();
    console.log('✅ Cleanup completed');
  }
}

// Run the test
testVerificationHistoryCreate()
  .then(success => {
    if (success) {
      console.log('\n🎉 TEST PASSED: createdAt column fix is working correctly');
      process.exit(0);
    } else {
      console.log('\n❌ TEST FAILED: createdAt column fix needs more work');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('Test execution failed:', error);
    process.exit(1);
  });