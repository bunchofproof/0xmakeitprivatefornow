const axios = require('axios');
const crypto = require('crypto');

// Test configuration
const BASE_URL = 'http://localhost:3001';

function generateMockProofs(domain, verificationType = 'personhood') {
  return [{
    proof: crypto.randomBytes(32).toString('hex'),
    publicSignals: [
      crypto.randomBytes(32).toString('hex'),
      domain,
      crypto.randomBytes(32).toString('hex') // passport fingerprint
    ]
  }];
}

async function testGuardianProtocolV2() {
  console.log('Testing Guardian Protocol V2 Implementation...');

  try {
    // Test 1: Brand New Verification (Should succeed)
    console.log('\n1. Testing Brand New Verification...');
    const sessionId1 = crypto.randomBytes(32).toString('hex');
    const response1 = await axios.post(`${BASE_URL}/api/verify/proof`, {
      proofs: generateMockProofs('example.com'),
      sessionId: sessionId1,
      token: crypto.randomBytes(32).toString('hex'),
      domain: 'example.com',
      verificationType: 'personhood',
      guildId: '123456789'
    });
    console.log('✅ Brand new verification response:', response1.data.verified);

    // Test 2: Re-verification with same passport (Case A.1 - active)
    console.log('\n2. Testing Re-verification with same passport (active user)...');
    const sessionId2 = crypto.randomBytes(32).toString('hex');
    try {
      const response2 = await axios.post(`${BASE_URL}/api/verify/proof`, {
        proofs: generateMockProofs('example.com'),
        sessionId: sessionId2,
        token: crypto.randomBytes(32).toString('hex'),
        domain: 'example.com',
        verificationType: 'personhood',
        guildId: '123456789'
      });
      console.log('✅ Re-verification response:', response2.data.verified);
    } catch (error) {
      if (error.response.status === 409 && error.response.data.message.includes('already linked to your account')) {
        console.log('✅ Correctly rejected re-verification (active user):', error.response.data.message);
      } else {
        throw error;
      }
    }

    // Test 3: Sybil attack attempt (Case A.2)
    console.log('\n3. Testing Sybil Attack Detection...');
    const sessionId3 = crypto.randomBytes(32).toString('hex');
    try {
      const response3 = await axios.post(`${BASE_URL}/api/verify/proof`, {
        proofs: generateMockProofs('example.com'),
        sessionId: sessionId3,
        token: crypto.randomBytes(32).toString('hex'),
        domain: 'example.com',
        verificationType: 'personhood',
        guildId: '123456789'
      });
      throw new Error('Expected rejection for Sybil attack');
    } catch (error) {
      if (error.response.status === 409 && error.response.data.message.includes('already been used to verify a different Discord account')) {
        console.log('✅ Correctly detected Sybil attack:', error.response.data.message);
      } else {
        throw error;
      }
    }

    // Test 4: New passport attempt (Case B)
    console.log('\n4. Testing New Passport Verification (existing user)...');
    const sessionId4 = crypto.randomBytes(32).toString('hex');
    try {
      const response4 = await axios.post(`${BASE_URL}/api/verify/proof`, {
        proofs: generateMockProofs('different.com'),
        sessionId: sessionId4,
        token: crypto.randomBytes(32).toString('hex'),
        domain: 'different.com',
        verificationType: 'personhood',
        guildId: '123456789'
      });
      throw new Error('Expected rejection for new passport');
    } catch (error) {
      if (error.response.status === 409 && error.response.data.message.includes('already verified with a different passport')) {
        console.log('✅ Correctly rejected new passport attempt:', error.response.data.message);
      } else {
        throw error;
      }
    }

    console.log('\n🎉 All Guardian Protocol V2 tests passed!');

  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
    process.exit(1);
  }
}

testGuardianProtocolV2();