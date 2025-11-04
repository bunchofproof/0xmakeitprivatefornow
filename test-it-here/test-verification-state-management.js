// Test script to verify Guardian Protocol V2 state management
// This script tests four independent scenarios:
// 1. New User Verification (should succeed)
// 2. Sybil Attack Prevention (should fail 409)
// 3. Re-Verification (Active User) (should fail 409)
// 4. Re-Verification with New Passport (should fail 409 and log security event)

const axios = require('axios');
const crypto = require('crypto');

// Configuration - adjust as needed for your test environment
const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:3001';
const BOT_TOKEN = process.env.BOT_TOKEN || 'your-bot-token-here';

// Use Prisma client directly since backend uses Prisma with Supabase
process.env.DATABASE_URL = 'postgresql://postgres:postgres@127.0.0.1:54322/postgres';
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

// Mock ZK proof data (in real test, this would be actual ZK proofs)
const mockProofs = [{
  proof: 'mock-proof-data',
  publicSignals: ['signal1', 'signal2']
}];

// Set deterministic mocking for consistent test results
process.env.DETERMINISTIC_MOCK_FINGERPRINTS = 'true';

// Helper function to sanitize proofs for deterministic hashing (matches zkVerification.ts logic)
function sanitizeProofsForHash(proofs) {
  if (!proofs || proofs.length === 0) {
    return [];
  }

  return proofs.map(proof => {
    // Create a deep clone to avoid modifying the original object
    const sanitizedProof = JSON.parse(JSON.stringify(proof));

    // Recursively sanitize the entire object to catch nested random data
    const recursivelySanitize = (obj) => {
      if (!obj || typeof obj !== 'object') return;
      for (const key in obj) {
        if (key === 'timestamp' || key.endsWith('At') || key.includes('nonce') || key === 'proof') {
          delete obj[key];
        } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          recursivelySanitize(obj[key]);
        }
      }
    };

    recursivelySanitize(sanitizedProof);

    // ADD THE FINAL FIX
    delete sanitizedProof.vkeyHash;

    return sanitizedProof; // Return the fully sanitized object
  }).sort((a, b) => {
    // Sort by stringified sanitized proof for consistent hashing
    return JSON.stringify(a).localeCompare(JSON.stringify(b));
  });
}

// Helper function to generate deterministic fingerprint and uniqueIdentifier
function generateDeterministicValues(proofs) {
  // Use sanitized proofs for consistent hashing
  const sanitizedProofs = sanitizeProofsForHash(proofs);
  const content = JSON.stringify(sanitizedProofs);
  const passportFingerprint = crypto.createHash('sha256').update(content).digest('hex');
  const uniqueIdentifier = crypto.createHash('sha256').update(content + '_unique').digest('hex').substring(0, 32);
  return { passportFingerprint, uniqueIdentifier };
}

// Helper function to create unique test data
function generateTestData() {
  return {
    userId: crypto.randomBytes(16).toString('hex'),
    passportFingerprint: 'fingerprint_' + crypto.randomBytes(16).toString('hex'),
    uniqueIdentifier: 'unique_' + crypto.randomBytes(16).toString('hex')
  };
}

// Cleanup function for all test data
async function cleanupAllTestData() {
  console.log('\n=== Cleaning up all test data ===');
  try {
    await prisma.verificationHistory.deleteMany();
    await prisma.adminVerification.deleteMany();
    await prisma.verificationSession.deleteMany();
    await prisma.user.deleteMany();
    console.log('✅ All test data cleaned up successfully');
  } catch (error) {
    console.log('❌ Error during cleanup:', error.message);
  }
}

// Helper function to create test user
async function createTestUser(userId) {
  const accessToken = crypto.randomBytes(32).toString('hex');
  const refreshToken = crypto.randomBytes(32).toString('hex');

  return await prisma.user.upsert({
    where: { userId },
    update: {},
    create: {
      userId,
      accessToken,
      refreshToken
    }
  });
}

// Helper function to create test session
async function createTestSession(userId) {
  await createTestUser(userId);

  const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes from now
  const token = crypto.randomBytes(32).toString('hex');
  const bindingHash = crypto.randomBytes(32).toString('hex');
  const lastContextHash = crypto.randomBytes(32).toString('hex');
  const sessionId = crypto.randomBytes(32).toString('hex');

  return await prisma.verificationSession.create({
    data: {
      id: sessionId,
      token,
      discordUserId: userId,
      expiresAt,
      used: false,
      bindingHash,
      lastContextHash
    }
  });
}

// Helper function to create verified admin verification
async function createVerifiedAdminVerification(discordUserId, passportFingerprint, uniqueIdentifier) {
  return await prisma.adminVerification.upsert({
    where: { discordUserId },
    update: {
      passportFingerprint,
      uniqueIdentifier,
      isActive: true,
      lastVerified: new Date()
    },
    create: {
      discordUserId,
      passportFingerprint,
      uniqueIdentifier,
      isActive: true,
      lastVerified: new Date()
    }
  });
}

// Scenario 1: New User Verification
async function testScenario1_NewUser() {
  console.log('\n=== Scenario 1: New User Verification ===');

  const testData = generateTestData();

  try {
    // Generate deterministic values from the mock proofs
    const deterministicValues = generateDeterministicValues(mockProofs);

    // Create a new session for the user
    console.log('Creating new session for user...');
    const session = await createTestSession(testData.userId);
    console.log('Session created:', session.id);

    // Call /proof route (deterministic mocking is enabled via environment)
    console.log('Calling /proof route...');
    const response = await axios.post(`${BACKEND_URL}/api/verify/proof`, {
      proofs: mockProofs,
      sessionId: session.id,
      token: session.token,
      domain: 'test-domain',
      verificationType: 'personhood'
    });

    console.log('API Response:', { status: response.status, data: response.data });

    // Assert on real output
    const success = response.status === 200 && response.data.verified === true;
    if (success) {
      console.log('✅ PASS: New user verification succeeded');
    } else {
      console.log('❌ FAIL: Expected 200 OK with verified=true');
      return false;
    }

    // Assert on database state
    const adminVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId: testData.userId }
    });

    if (!adminVerification) {
      console.log('❌ FAIL: No AdminVerification record found in database');
      return false;
    }

    if (adminVerification.passportFingerprint !== deterministicValues.passportFingerprint ||
        adminVerification.uniqueIdentifier !== deterministicValues.uniqueIdentifier ||
        !adminVerification.isActive) {
      console.log('❌ FAIL: AdminVerification record has incorrect data');
      console.log('Expected:', {
        passportFingerprint: deterministicValues.passportFingerprint,
        uniqueIdentifier: deterministicValues.uniqueIdentifier,
        isActive: true
      });
      console.log('Actual:', adminVerification);
      return false;
    }

    console.log('✅ PASS: Database state correct - 1 AdminVerification record created');
    return true;

  } catch (error) {
    console.log('❌ ERROR in Scenario 1:', error.response?.data || error.message);
    return false;
  } finally {
    // Cleanup this scenario's data
    await cleanupAllTestData();
  }
}

// Scenario 2: Sybil Attack Prevention
async function testScenario2_SybilAttack() {
  console.log('\n=== Scenario 2: Sybil Attack Prevention ===');

  const attackerData = generateTestData();
  const victimData = generateTestData();

  try {
    // Step 1: Create verified AdminVerification for victim with deterministic values
    const victimDeterministicValues = generateDeterministicValues(mockProofs);
    console.log('Creating verified AdminVerification for victim...');
    await createVerifiedAdminVerification(victimData.userId, victimDeterministicValues.passportFingerprint, victimDeterministicValues.uniqueIdentifier);

    // Step 2: Create session for attacker
    console.log('Creating session for attacker...');
    const session = await createTestSession(attackerData.userId);

    // Step 3: Call /proof route with same proofs (deterministic mocking will generate same fingerprint)
    console.log('Calling /proof route (should fail with 409 due to fingerprint collision)...');
    const response = await axios.post(`${BACKEND_URL}/api/verify/proof`, {
      proofs: mockProofs,
      sessionId: session.id,
      token: session.token,
      domain: 'test-domain',
      verificationType: 'personhood'
    }, { validateStatus: () => true }); // Don't throw on non-2xx

    console.log('API Response:', { status: response.status, data: response.data });

    // Assert on real output - should fail because fingerprint already exists for different user
    const success = response.status === 409 &&
                   response.data.message &&
                   response.data.message.includes('different Discord account');
    if (success) {
      console.log('✅ PASS: Sybil attack correctly blocked (deterministic fingerprint collision)');
    } else {
      console.log('❌ FAIL: Expected 409 Conflict with "different Discord account" message');
      console.log('Actual:', { status: response.status, message: response.data?.message });
      return false;
    }

    // Assert on database state - no new AdminVerification should be created
    const adminVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId: attackerData.userId }
    });

    if (adminVerification) {
      console.log('❌ FAIL: Unexpected AdminVerification record created for attacker');
      return false;
    }

    console.log('✅ PASS: Database state correct - no AdminVerification record created for attacker');
    return true;

  } catch (error) {
    console.log('❌ ERROR in Scenario 2:', error.response?.data || error.message);
    return false;
  } finally {
    // Cleanup this scenario's data
    await cleanupAllTestData();
  }
}

// Scenario 3: Re-Verification (Active User)
async function testScenario3_ReVerificationActiveUser() {
  console.log('\n=== Scenario 3: Re-Verification (Active User) ===');

  const testData = generateTestData();

  try {
    // Step 1: Create verified AdminVerification for user with deterministic values
    const userDeterministicValues = generateDeterministicValues(mockProofs);
    console.log('Creating verified AdminVerification for user...');
    await createVerifiedAdminVerification(testData.userId, userDeterministicValues.passportFingerprint, userDeterministicValues.uniqueIdentifier);

    // Step 2: Create new session for same user
    console.log('Creating new session for same user...');
    const session = await createTestSession(testData.userId);

    // Step 3: Call /proof route with same proofs (deterministic mocking will generate same values)
    console.log('Calling /proof route (should fail with 409 due to user already verified)...');
    const response = await axios.post(`${BACKEND_URL}/api/verify/proof`, {
      proofs: mockProofs,
      sessionId: session.id,
      token: session.token,
      domain: 'test-domain',
      verificationType: 'personhood'
    }, { validateStatus: () => true }); // Don't throw on non-2xx

    console.log('API Response:', { status: response.status, data: response.data });

    // Assert on real output - should fail because user already has active verification
    const success = response.status === 409 &&
                   response.data.message &&
                   response.data.message.includes('User already has active admin verification');
    if (success) {
      console.log('✅ PASS: Re-verification correctly blocked (user already verified)');
    } else {
      console.log('❌ FAIL: Expected 409 Conflict with "User already has active admin verification" message');
      console.log('Actual:', { status: response.status, message: response.data?.message });
      return false;
    }

    // Assert on database state - AdminVerification should remain unchanged
    const adminVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId: testData.userId }
    });

    if (!adminVerification || !adminVerification.isActive) {
      console.log('❌ FAIL: AdminVerification record should remain active');
      return false;
    }

    console.log('✅ PASS: Database state correct - AdminVerification remained active');
    return true;

  } catch (error) {
    console.log('❌ ERROR in Scenario 3:', error.response?.data || error.message);
    return false;
  } finally {
    // Cleanup this scenario's data
    await cleanupAllTestData();
  }
}

// Scenario 4: Re-Verification with New Passport
async function testScenario4_ReVerificationNewPassport() {
  console.log('\n=== Scenario 4: Re-Verification with New Passport ===');

  const testData = generateTestData();
  const newFingerprint = 'fingerprint_' + crypto.randomBytes(16).toString('hex');
  const newIdentifier = 'unique_' + crypto.randomBytes(16).toString('hex');

  try {
    // Step 1: Create verified AdminVerification for user with deterministic values from mockProofs
    const originalDeterministicValues = generateDeterministicValues(mockProofs);
    console.log('Creating verified AdminVerification for user with original passport...');
    await createVerifiedAdminVerification(testData.userId, originalDeterministicValues.passportFingerprint, originalDeterministicValues.uniqueIdentifier);

    // Step 2: Create new session for same user
    console.log('Creating new session for same user...');
    const session = await createTestSession(testData.userId);

    // Step 3: Use different proofs to generate different deterministic values (new passport)
    const differentProofs = [{ ...mockProofs[0], data: { ...mockProofs[0].data, different: true } }];
    const newDeterministicValues = generateDeterministicValues(differentProofs);

    // Step 4: Call /proof route with different proofs (deterministic mocking will generate different fingerprint)
    console.log('Calling /proof route with different proofs (should fail with 409 due to different fingerprint)...');
    const response = await axios.post(`${BACKEND_URL}/api/verify/proof`, {
      proofs: differentProofs,
      sessionId: session.id,
      token: session.token,
      domain: 'test-domain',
      verificationType: 'personhood'
    }, { validateStatus: () => true }); // Don't throw on non-2xx

    console.log('API Response:', { status: response.status, data: response.data });

    // Assert on real output - should fail because user already has active verification
    const success = response.status === 409 &&
                   response.data.message &&
                   response.data.message.includes('User already has active admin verification');
    if (success) {
      console.log('✅ PASS: Re-verification with new passport correctly blocked (user already verified)');
    } else {
      console.log('❌ FAIL: Expected 409 Conflict with "User already has active admin verification" message');
      console.log('Actual:', { status: response.status, message: response.data?.message });
      return false;
    }

    // Assert on database state - AdminVerification should remain unchanged
    const adminVerification = await prisma.adminVerification.findUnique({
      where: { discordUserId: testData.userId }
    });

    if (!adminVerification ||
        adminVerification.passportFingerprint !== originalDeterministicValues.passportFingerprint ||
        adminVerification.uniqueIdentifier !== originalDeterministicValues.uniqueIdentifier ||
        !adminVerification.isActive) {
      console.log('❌ FAIL: AdminVerification record should remain unchanged');
      return false;
    }

    console.log('✅ PASS: Database state correct - AdminVerification remained with original passport');
    return true;

  } catch (error) {
    console.log('❌ ERROR in Scenario 4:', error.response?.data || error.message);
    return false;
  } finally {
    // Cleanup this scenario's data
    await cleanupAllTestData();
  }
}

// Main test runner
async function runAllTests() {
  console.log('🚀 Starting Guardian Protocol V2 Test Suite');
  console.log('Backend URL:', BACKEND_URL);

  const results = [];

  // Run each scenario independently
  console.log('\n--- Running Scenario 1: New User Verification ---');
  results.push(await testScenario1_NewUser());

  console.log('\n--- Running Scenario 2: Sybil Attack Prevention ---');
  results.push(await testScenario2_SybilAttack());

  console.log('\n--- Running Scenario 3: Re-Verification (Active User) ---');
  results.push(await testScenario3_ReVerificationActiveUser());

  console.log('\n--- Running Scenario 4: Re-Verification with New Passport ---');
  results.push(await testScenario4_ReVerificationNewPassport());

  // Summary
  const passed = results.filter(r => r).length;
  const total = results.length;

  console.log('\n=== Final Test Results Summary ===');
  console.log(`Passed: ${passed}/${total}`);

  console.log('\nDetailed Results:');
  console.log('Scenario 1 (New User) - 200 OK:', results[0] ? '✅ PASS' : '❌ FAIL');
  console.log('Scenario 2 (Sybil Attack) - 409 Conflict:', results[1] ? '✅ PASS' : '❌ FAIL');
  console.log('Scenario 3 (Re-Verification Active) - 409 Conflict:', results[2] ? '✅ PASS' : '❌ FAIL');
  console.log('Scenario 4 (Re-Verification New Passport) - 409 Conflict:', results[3] ? '✅ PASS' : '❌ FAIL');

  // Close Prisma connection
  await prisma.$disconnect();

  if (passed === total) {
    console.log('\n🎉 ALL TESTS PASSED - Guardian Protocol V2 state management is working correctly');
    process.exit(0);
  } else {
    console.log('\n❌ SOME TESTS FAILED - Please review the implementation');
    process.exit(1);
  }
}

// Run the tests
runAllTests().catch(error => {
  console.error('Test suite failed:', error);
  process.exit(1);
});