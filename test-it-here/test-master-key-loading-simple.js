#!/usr/bin/env node

// Simple test to verify MASTER_ENCRYPTION_KEY loading

require('dotenv').config({ path: '../backend/.env.development' });

console.log('Testing MASTER_ENCRYPTION_KEY environment variable...');

const key = process.env.MASTER_ENCRYPTION_KEY;

if (!key) {
  console.error('❌ MASTER_ENCRYPTION_KEY is not set');
  process.exit(1);
}

if (key.length < 16) {
  console.error('❌ MASTER_ENCRYPTION_KEY is too short (minimum 16 characters)');
  process.exit(1);
}

console.log('✅ MASTER_ENCRYPTION_KEY is properly configured');
console.log('✅ All verification tests passed!');

process.exit(0);